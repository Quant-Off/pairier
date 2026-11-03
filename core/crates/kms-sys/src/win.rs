use core::ffi::c_void;
use core::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
    SDDL_REVISION_1, SE_OBJECT_TYPE,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CopySid,
    CreateWellKnownSid, DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorDacl, GetTokenInformation, IsValidSid, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
    TOKEN_USER, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::error::Error;

const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

#[derive(Debug, Clone)]
pub(crate) struct Sid {
    words: Vec<u32>,
    len: usize,
}

impl PartialEq for Sid {
    fn eq(&self, other: &Self) -> bool {
        self.bytes() == other.bytes()
    }
}

impl Eq for Sid {}

impl Sid {
    fn with_capacity(bytes: usize) -> Self {
        Self {
            words: vec![0u32; bytes.div_ceil(4)],
            len: 0,
        }
    }

    fn bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }

    pub(crate) fn as_psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast::<c_void>()
    }

    unsafe fn from_psid(op: &'static str, psid: PSID) -> Result<Self, Error> {
        if psid.is_null() || unsafe { IsValidSid(psid) } == 0 {
            return Err(Error::invalid(op, "invalid sid"));
        }
        let len = unsafe { GetLengthSid(psid) };
        let n = usize::try_from(len).map_err(|_| Error::invalid(op, "sid length overflow"))?;
        let mut sid = Self::with_capacity(n);
        if unsafe { CopySid(len, sid.as_psid(), psid) } == 0 {
            return Err(Error::last("CopySid"));
        }
        sid.len = n;
        Ok(sid)
    }

    pub(crate) fn display(&self) -> Result<String, Error> {
        let mut out: *mut u16 = null_mut();
        if unsafe { ConvertSidToStringSidW(self.as_psid(), &raw mut out) } == 0 {
            return Err(Error::last("ConvertSidToStringSidW"));
        }
        let s = unsafe { wide_to_string(out) };
        unsafe {
            LocalFree(out.cast::<c_void>());
        }
        Ok(s)
    }
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

unsafe fn wide_to_string(p: *const u16) -> String {
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 {
        len = len.saturating_add(1);
    }
    String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(p, len) })
}

unsafe fn token_user_sid(token: HANDLE) -> Result<Sid, Error> {
    let mut needed: u32 = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &raw mut needed);
    }
    if needed == 0 {
        return Err(Error::last("GetTokenInformation"));
    }
    let words = usize::try_from(needed)
        .map_err(|_| Error::invalid("GetTokenInformation", "length overflow"))?
        .div_ceil(8);
    let mut buf = vec![0u64; words];
    let rc = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &raw mut needed,
        )
    };
    if rc == 0 {
        return Err(Error::last("GetTokenInformation"));
    }
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    unsafe { Sid::from_psid("GetTokenInformation", user.User.Sid) }
}

pub(crate) fn current_user_sid() -> Result<Sid, Error> {
    let mut token: HANDLE = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(Error::last("OpenProcessToken"));
    }
    let sid = unsafe { token_user_sid(token) };
    unsafe {
        CloseHandle(token);
    }
    sid
}

pub(crate) fn process_user_sid(pid: u32) -> Result<Sid, Error> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(Error::last("OpenProcess"));
    }
    let mut token: HANDLE = null_mut();
    let opened = unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) };
    let open_err = (opened == 0).then(|| Error::last("OpenProcessToken"));
    unsafe {
        CloseHandle(process);
    }
    if let Some(e) = open_err {
        return Err(e);
    }
    let sid = unsafe { token_user_sid(token) };
    unsafe {
        CloseHandle(token);
    }
    sid
}

pub(crate) fn local_system_sid() -> Result<Sid, Error> {
    let cap = usize::try_from(SECURITY_MAX_SID_SIZE)
        .map_err(|_| Error::invalid("CreateWellKnownSid", "size overflow"))?;
    let mut sid = Sid::with_capacity(cap);
    let mut size: u32 = SECURITY_MAX_SID_SIZE;
    let rc =
        unsafe { CreateWellKnownSid(WinLocalSystemSid, null_mut(), sid.as_psid(), &raw mut size) };
    if rc == 0 {
        return Err(Error::last("CreateWellKnownSid"));
    }
    sid.len =
        usize::try_from(size).map_err(|_| Error::invalid("CreateWellKnownSid", "size overflow"))?;
    Ok(sid)
}

#[derive(Debug)]
pub(crate) struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    pub(crate) fn from_sddl(sddl: &str) -> Result<Self, Error> {
        let text = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let rc = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut sd,
                null_mut(),
            )
        };
        if rc == 0 || sd.is_null() {
            return Err(Error::last(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW",
            ));
        }
        Ok(Self(sd))
    }

    pub(crate) fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }

    pub(crate) fn dacl(&self) -> Result<*mut ACL, Error> {
        let mut present: i32 = 0;
        let mut defaulted: i32 = 0;
        let mut acl: *mut ACL = null_mut();
        let rc = unsafe {
            GetSecurityDescriptorDacl(self.0, &raw mut present, &raw mut acl, &raw mut defaulted)
        };
        if rc == 0 {
            return Err(Error::last("GetSecurityDescriptorDacl"));
        }
        if present == 0 || acl.is_null() {
            return Err(Error::invalid(
                "GetSecurityDescriptorDacl",
                "descriptor has no DACL",
            ));
        }
        Ok(acl)
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

pub(crate) fn private_sddl(owner: &Sid) -> Result<String, Error> {
    Ok(format!("D:P(A;;FA;;;SY)(A;;FA;;;{})", owner.display()?))
}

pub(crate) struct Attributes {
    _descriptor: SecurityDescriptor,
    attrs: SECURITY_ATTRIBUTES,
}

impl Attributes {
    pub(crate) fn from_sddl(sddl: &str) -> Result<Self, Error> {
        let descriptor = SecurityDescriptor::from_sddl(sddl)?;
        let length = u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| Error::invalid("SECURITY_ATTRIBUTES", "size overflow"))?;
        let attrs = SECURITY_ATTRIBUTES {
            nLength: length,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        Ok(Self {
            _descriptor: descriptor,
            attrs,
        })
    }

    pub(crate) fn private(owner: &Sid) -> Result<Self, Error> {
        Self::from_sddl(&private_sddl(owner)?)
    }

    pub(crate) fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &raw const self.attrs
    }
}

impl core::fmt::Debug for Attributes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Attributes").finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Ace {
    pub(crate) kind: u8,
    #[allow(dead_code)]
    pub(crate) mask: u32,
    pub(crate) sid: Sid,
}

#[derive(Debug, Clone)]
pub(crate) struct ObjectSecurity {
    pub(crate) owner: Option<Sid>,
    pub(crate) dacl: Option<Vec<Ace>>,
}

pub(crate) fn object_security(
    handle: HANDLE,
    kind: SE_OBJECT_TYPE,
) -> Result<ObjectSecurity, Error> {
    let mut owner_sid: PSID = null_mut();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            handle,
            kind,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner_sid,
            null_mut(),
            &raw mut dacl,
            null_mut(),
            &raw mut descriptor,
        )
    };
    if rc != 0 {
        return Err(Error::code("GetSecurityInfo", rc));
    }
    let result = unsafe { collect(owner_sid, dacl) };
    unsafe {
        LocalFree(descriptor);
    }
    result
}

unsafe fn collect(owner_sid: PSID, dacl: *const ACL) -> Result<ObjectSecurity, Error> {
    let owner = if owner_sid.is_null() {
        None
    } else {
        Some(unsafe { Sid::from_psid("GetSecurityInfo", owner_sid) }?)
    };
    if dacl.is_null() {
        return Ok(ObjectSecurity { owner, dacl: None });
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { core::mem::zeroed() };
    let info_len = u32::try_from(size_of::<ACL_SIZE_INFORMATION>())
        .map_err(|_| Error::invalid("GetAclInformation", "size overflow"))?;
    let rc = unsafe {
        GetAclInformation(
            dacl,
            (&raw mut info).cast::<c_void>(),
            info_len,
            AclSizeInformation,
        )
    };
    if rc == 0 {
        return Err(Error::last("GetAclInformation"));
    }
    let mut entries = Vec::new();
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &raw mut ace) } == 0 || ace.is_null() {
            return Err(Error::last("GetAce"));
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType > ACCESS_DENIED_ACE_TYPE {
            return Err(Error::invalid("GetAce", "unsupported ACE type"));
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&raw const allowed.SidStart).cast_mut().cast::<c_void>();
        entries.push(Ace {
            kind: header.AceType,
            mask: allowed.Mask,
            sid: unsafe { Sid::from_psid("GetAce", sid) }?,
        });
    }
    Ok(ObjectSecurity {
        owner,
        dacl: Some(entries),
    })
}

pub(crate) fn check_private_object(
    handle: HANDLE,
    kind: SE_OBJECT_TYPE,
    owner: &Sid,
) -> Result<(), Error> {
    let security = object_security(handle, kind)?;
    if security.owner.as_ref() != Some(owner) {
        return Err(Error::invalid(
            "GetSecurityInfo",
            "object is not owned by the current user",
        ));
    }
    let Some(entries) = security.dacl else {
        return Err(Error::invalid("GetSecurityInfo", "object has no DACL"));
    };
    let system = local_system_sid()?;
    for ace in &entries {
        if ace.kind != ACCESS_ALLOWED_ACE_TYPE {
            return Err(Error::invalid(
                "GetSecurityInfo",
                "object DACL contains an entry that is not an allow entry",
            ));
        }
        if ace.sid != *owner && ace.sid != system {
            return Err(Error::invalid(
                "GetSecurityInfo",
                "object grants access to other users",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        Attributes, SecurityDescriptor, current_user_sid, local_system_sid, private_sddl,
        process_user_sid,
    };

    #[test]
    fn current_user_matches_own_process() {
        let me = current_user_sid().unwrap();
        let by_pid = process_user_sid(std::process::id()).unwrap();
        assert_eq!(me, by_pid);
        assert!(me.display().unwrap().starts_with("S-1-"));
        assert_ne!(me, local_system_sid().unwrap());
        assert_eq!(local_system_sid().unwrap().display().unwrap(), "S-1-5-18");
    }

    #[test]
    fn sddl_round_trips() {
        let me = current_user_sid().unwrap();
        let sd = SecurityDescriptor::from_sddl(&private_sddl(&me).unwrap()).unwrap();
        assert!(!sd.dacl().unwrap().is_null());
        let attrs = Attributes::private(&me).unwrap();
        assert!(!attrs.as_ptr().is_null());
        assert!(SecurityDescriptor::from_sddl("not sddl").is_err());
    }
}
