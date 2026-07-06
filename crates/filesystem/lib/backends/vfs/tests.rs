//! Scaffold tests: drive [`VirtualFs`] over the in-process [`InMemoryFs`]
//! provider directly through the [`DynFileSystem`] interface.

#![cfg(test)]

use std::ffi::CString;

use super::test_backend::{
    InMemoryFs, LINUX_EINVAL, LINUX_EISDIR, LINUX_ENOENT, MockReader, MockWriter,
};
use super::{NodeKind, PathFs, VAttr, VirtualFs};
use crate::backends::shared::platform;
use crate::{Context, DynFileSystem, Extensions, SetattrValid, stat64};

const ROOT: u64 = 1;

fn ctx() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 0,
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn fs() -> VirtualFs<InMemoryFs> {
    VirtualFs::new(InMemoryFs::new()).unwrap()
}

/// `st_mode`'s `S_IFMT` type bits as a `u32` (the field is `u16` on macOS,
/// `u32` on linux/windows — hence the allow).
#[allow(clippy::unnecessary_cast)]
fn ftype(st: &stat64) -> u32 {
    (st.st_mode as u32) & platform::MODE_TYPE_MASK
}

/// The errno of a result that is expected to be an error (the `Ok` type need not
/// be `Debug`, unlike `Result::unwrap_err`).
fn err_no<T>(r: std::io::Result<T>) -> Option<i32> {
    r.err().expect("expected an error").raw_os_error()
}

/// Create + open a file under root, returning `(inode, handle)`.
fn create_file(fs: &VirtualFs<InMemoryFs>, name: &str) -> (u64, u64) {
    let (entry, handle, _) = fs
        .create(
            ctx(),
            ROOT,
            &cstr(name),
            0o644,
            false,
            0,
            0,
            Extensions::default(),
        )
        .expect("create");
    (entry.inode, handle.expect("handle"))
}

fn write_all(fs: &VirtualFs<InMemoryFs>, ino: u64, handle: u64, offset: u64, data: &[u8]) -> usize {
    let mut reader = MockReader::new(data.to_vec());
    fs.write(
        ctx(),
        ino,
        handle,
        &mut reader,
        data.len() as u32,
        offset,
        None,
        false,
        false,
        0,
    )
    .expect("write")
}

fn read_all(fs: &VirtualFs<InMemoryFs>, ino: u64, handle: u64, offset: u64, size: u32) -> Vec<u8> {
    let mut writer = MockWriter::new();
    fs.read(ctx(), ino, handle, &mut writer, size, offset, None, 0)
        .expect("read");
    writer.buf
}

#[test]
fn lookup_missing_is_enoent() {
    let fs = fs();
    assert_eq!(
        err_no(fs.lookup(ctx(), ROOT, &cstr("nope"))),
        Some(LINUX_ENOENT)
    );
}

#[test]
fn create_write_read_round_trips() {
    let fs = fs();
    let (ino, handle) = create_file(&fs, "hello.txt");

    let payload = b"the quick brown fox";
    assert_eq!(write_all(&fs, ino, handle, 0, payload), payload.len());
    assert_eq!(read_all(&fs, ino, handle, 0, 64), payload);

    // getattr by inode reflects the written size.
    let (st, _) = fs.getattr(ctx(), ino, None).unwrap();
    assert_eq!(st.st_size as usize, payload.len());
    assert_eq!(ftype(&st), platform::MODE_REG);
}

#[test]
fn lookup_after_create_sees_file() {
    let fs = fs();
    create_file(&fs, "a.txt");
    let entry = fs.lookup(ctx(), ROOT, &cstr("a.txt")).unwrap();
    assert_eq!(ftype(&entry.attr), platform::MODE_REG);
}

#[test]
fn mkdir_then_readdir_lists_children() {
    let fs = fs();
    fs.mkdir(ctx(), ROOT, &cstr("dir"), 0o755, 0, Extensions::default())
        .unwrap();
    let dir = fs.lookup(ctx(), ROOT, &cstr("dir")).unwrap();
    create_file(&fs, "top.txt");

    // Create a child inside the directory.
    fs.create(
        ctx(),
        dir.inode,
        &cstr("inner.txt"),
        0o644,
        false,
        0,
        0,
        Extensions::default(),
    )
    .unwrap();

    let (handle, _) = fs.opendir(ctx(), dir.inode, 0).unwrap();
    let entries = fs
        .readdir(ctx(), dir.inode, handle.unwrap(), 4096, 0)
        .unwrap();
    let names: Vec<&[u8]> = entries.iter().map(|e| e.name).collect();
    assert!(names.contains(&b".".as_slice()));
    assert!(names.contains(&b"..".as_slice()));
    assert!(names.contains(&b"inner.txt".as_slice()));
    assert!(!names.contains(&b"top.txt".as_slice()));
}

#[test]
fn readdirplus_carries_attrs() {
    let fs = fs();
    create_file(&fs, "x.txt");
    let (handle, _) = fs.opendir(ctx(), ROOT, 0).unwrap();
    let entries = fs
        .readdirplus(ctx(), ROOT, handle.unwrap(), 4096, 0)
        .unwrap();
    let x = entries
        .iter()
        .find(|(de, _)| de.name == b"x.txt")
        .expect("x.txt present");
    assert_eq!(ftype(&x.1.attr), platform::MODE_REG);
}

#[test]
fn rename_moves_file() {
    let fs = fs();
    let (ino, handle) = create_file(&fs, "old.txt");
    write_all(&fs, ino, handle, 0, b"data");

    fs.rename(ctx(), ROOT, &cstr("old.txt"), ROOT, &cstr("new.txt"), 0)
        .unwrap();

    assert_eq!(
        err_no(fs.lookup(ctx(), ROOT, &cstr("old.txt"))),
        Some(LINUX_ENOENT)
    );
    let moved = fs.lookup(ctx(), ROOT, &cstr("new.txt")).unwrap();
    // The handle opened before the rename still reads the moved content.
    assert_eq!(read_all(&fs, moved.inode, handle, 0, 64), b"data");
}

#[test]
fn unlink_removes_file_and_rejects_dir() {
    let fs = fs();
    create_file(&fs, "f.txt");
    fs.mkdir(ctx(), ROOT, &cstr("d"), 0o755, 0, Extensions::default())
        .unwrap();

    fs.unlink(ctx(), ROOT, &cstr("f.txt")).unwrap();
    assert_eq!(
        err_no(fs.lookup(ctx(), ROOT, &cstr("f.txt"))),
        Some(LINUX_ENOENT)
    );

    // unlink on a directory is EISDIR.
    assert_eq!(
        err_no(fs.unlink(ctx(), ROOT, &cstr("d"))),
        Some(LINUX_EISDIR)
    );
}

#[test]
fn rmdir_requires_empty() {
    let fs = fs();
    fs.mkdir(ctx(), ROOT, &cstr("d"), 0o755, 0, Extensions::default())
        .unwrap();
    let d = fs.lookup(ctx(), ROOT, &cstr("d")).unwrap();
    fs.create(
        ctx(),
        d.inode,
        &cstr("child"),
        0o644,
        false,
        0,
        0,
        Extensions::default(),
    )
    .unwrap();

    // The scaffold is Linux-guest-facing, so it emits the Linux wire errno.
    assert_eq!(
        err_no(fs.rmdir(ctx(), ROOT, &cstr("d"))),
        platform::enotempty().raw_os_error()
    );
    fs.unlink(ctx(), d.inode, &cstr("child")).unwrap();
    fs.rmdir(ctx(), ROOT, &cstr("d")).unwrap();
    assert_eq!(
        err_no(fs.lookup(ctx(), ROOT, &cstr("d"))),
        Some(LINUX_ENOENT)
    );
}

#[test]
fn symlink_and_readlink_round_trip() {
    let fs = fs();
    let entry = fs
        .symlink(
            ctx(),
            &cstr("target.txt"),
            ROOT,
            &cstr("link"),
            Extensions::default(),
        )
        .unwrap();
    assert_eq!(ftype(&entry.attr), platform::MODE_LNK);
    let target = fs.readlink(ctx(), entry.inode).unwrap();
    assert_eq!(target, b"target.txt");
}

#[test]
fn readdir_paginates_and_returns_every_entry_once() {
    let fs = fs();
    let total = 50usize;
    for i in 0..total {
        create_file(&fs, &format!("f{i:02}"));
    }
    let (h, _) = fs.opendir(ctx(), ROOT, 0).unwrap();
    let h = h.unwrap();

    // A small reply buffer forces multiple pages.
    let first = fs.readdir(ctx(), ROOT, h, 200, 0).unwrap();
    assert!(!first.is_empty());
    assert!(
        first.len() < total + 2,
        "small buffer must not return the whole listing in one page"
    );

    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0u64;
    let mut pages = 0;
    loop {
        let page = fs.readdir(ctx(), ROOT, h, 200, offset).unwrap();
        if page.is_empty() {
            break;
        }
        for de in &page {
            names.push(de.name.to_vec());
            offset = de.offset;
        }
        pages += 1;
        assert!(pages < 1000, "pagination did not terminate");
    }
    assert!(pages > 1, "expected multiple pages");

    let unique: std::collections::BTreeSet<_> = names.iter().cloned().collect();
    assert_eq!(
        unique.len(),
        names.len(),
        "an entry was served on more than one page"
    );
    assert!(unique.contains(b".".as_slice()));
    assert!(unique.contains(b"..".as_slice()));
    for i in 0..total {
        assert!(
            unique.contains(format!("f{i:02}").as_bytes()),
            "missing entry f{i:02}"
        );
    }
    assert_eq!(unique.len(), total + 2);
}

#[test]
fn readdirplus_paginates_with_small_buffer() {
    // readdirplus takes a lookup reference per returned entry; bounding the page
    // to the buffer keeps it from referencing entries the kernel would drop.
    let fs = fs();
    let total = 40usize;
    for i in 0..total {
        create_file(&fs, &format!("p{i:02}"));
    }
    let (h, _) = fs.opendir(ctx(), ROOT, 0).unwrap();
    let h = h.unwrap();

    // A modest buffer (well above the dot-entry overhead, as a real kernel
    // always provides) yields several entries but not the whole listing.
    let first = fs.readdirplus(ctx(), ROOT, h, 2000, 0).unwrap();
    assert!(!first.is_empty());
    assert!(
        first.len() < total,
        "readdirplus must paginate under a modest buffer"
    );

    let mut names: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0u64;
    loop {
        let page = fs.readdirplus(ctx(), ROOT, h, 2000, offset).unwrap();
        if page.is_empty() {
            break;
        }
        for (de, ent) in &page {
            if de.name != b"." && de.name != b".." {
                assert_eq!(ftype(&ent.attr), platform::MODE_REG);
            }
            names.push(de.name.to_vec());
            offset = de.offset;
        }
        assert!(names.len() < 100_000, "pagination did not terminate");
    }
    for i in 0..total {
        assert!(
            names.contains(&format!("p{i:02}").into_bytes()),
            "missing p{i:02}"
        );
    }
}

#[test]
fn symlink_rejects_empty_target() {
    let fs = fs();
    assert_eq!(
        err_no(fs.symlink(ctx(), &cstr(""), ROOT, &cstr("link"), Extensions::default())),
        Some(LINUX_EINVAL)
    );
}

#[test]
fn setattr_truncate_changes_size() {
    let fs = fs();
    let (ino, handle) = create_file(&fs, "t.txt");
    write_all(&fs, ino, handle, 0, b"0123456789");

    let mut st: stat64 = unsafe { std::mem::zeroed() };
    st.st_size = 4;
    let (new, _) = fs
        .setattr(ctx(), ino, st, None, SetattrValid::SIZE)
        .unwrap();
    assert_eq!(new.st_size, 4);
    assert_eq!(read_all(&fs, ino, handle, 0, 64), b"0123");
}

#[test]
fn xattr_set_get_list_remove() {
    let fs = fs();
    let (ino, _) = create_file(&fs, "x.txt");
    fs.setxattr(ctx(), ino, &cstr("user.k"), b"v", 0).unwrap();

    match fs.getxattr(ctx(), ino, &cstr("user.k"), 64).unwrap() {
        crate::GetxattrReply::Value(v) => assert_eq!(v, b"v"),
        _ => panic!("unexpected getxattr reply"),
    }
    fs.removexattr(ctx(), ino, &cstr("user.k")).unwrap();
    assert!(fs.getxattr(ctx(), ino, &cstr("user.k"), 64).is_err());
}

#[test]
fn lookup_rejects_traversal_names() {
    let fs = fs();
    assert!(fs.lookup(ctx(), ROOT, &cstr("..")).is_err());
}

#[test]
fn readdirplus_skips_a_vanished_child_instead_of_aborting() {
    // A provider that lists two children but whose getattr fails for one of
    // them, as if "/bad" was removed between the directory snapshot and the
    // per-child getattr. Like memfs, the scaffold must skip the unresolvable
    // entry rather than failing the whole listing — and must not intern (take a
    // lookup reference for) the abandoned entry.
    struct Flaky;
    impl PathFs for Flaky {
        fn getattr(&self, path: &[u8]) -> std::io::Result<VAttr> {
            match path {
                b"/" => Ok(VAttr::dir(0o755)),
                b"/good" => Ok(VAttr::file(0o644, 0)),
                _ => Err(std::io::Error::from_raw_os_error(LINUX_ENOENT)),
            }
        }
        fn readdir(&self, _: &[u8]) -> std::io::Result<Vec<super::VDirEntry>> {
            Ok(vec![
                super::VDirEntry::new(b"good".to_vec(), NodeKind::File),
                super::VDirEntry::new(b"bad".to_vec(), NodeKind::File),
            ])
        }
        fn read(&self, _: &[u8], _: u64, _: u32) -> std::io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    let fs = VirtualFs::new(Flaky).unwrap();
    let (h, _) = fs.opendir(ctx(), ROOT, 0).unwrap();

    let entries = fs
        .readdirplus(ctx(), ROOT, h.unwrap(), 4096, 0)
        .expect("one bad child must not fail the whole readdirplus");
    let names: Vec<&[u8]> = entries.iter().map(|(de, _)| de.name).collect();
    assert!(
        names.contains(&b"good".as_slice()),
        "good child must be listed"
    );
    assert!(
        !names.contains(&b"bad".as_slice()),
        "vanished child must be skipped"
    );

    // The skipped child is never interned, so no lookup reference is leaked.
    assert!(
        fs.inodes
            .read()
            .unwrap()
            .get_alt(b"/bad".as_slice())
            .is_none(),
        "no node should be interned for the vanished child"
    );
}

#[test]
fn provider_is_accessible() {
    let fs = fs();
    create_file(&fs, "p.txt");
    // The scaffold and the provider agree on what exists.
    let provider: &InMemoryFs = fs.provider();
    assert!(provider.getattr(b"/p.txt").is_ok());
}

#[test]
fn read_only_provider_rejects_writes() {
    struct ReadOnly;
    impl PathFs for ReadOnly {
        fn getattr(&self, path: &[u8]) -> std::io::Result<VAttr> {
            match path {
                b"/" => Ok(VAttr::dir(0o755)),
                b"/readme" => Ok(VAttr::file(0o444, 5)),
                _ => Err(std::io::Error::from_raw_os_error(LINUX_ENOENT)),
            }
        }
        fn readdir(&self, _: &[u8]) -> std::io::Result<Vec<super::VDirEntry>> {
            Ok(vec![super::VDirEntry::new(
                b"readme".to_vec(),
                NodeKind::File,
            )])
        }
        fn read(&self, _: &[u8], _: u64, _: u32) -> std::io::Result<Vec<u8>> {
            Ok(b"hello".to_vec())
        }
    }
    let fs = VirtualFs::new(ReadOnly).unwrap();
    // create is unsupported -> ENOSYS (Linux wire value) from the default
    // PathFs::create.
    assert_eq!(
        err_no(fs.create(
            ctx(),
            ROOT,
            &cstr("x"),
            0o644,
            false,
            0,
            0,
            Extensions::default()
        )),
        platform::enosys().raw_os_error()
    );

    // ...but reading the read-only file works.
    let entry = fs.lookup(ctx(), ROOT, &cstr("readme")).unwrap();
    let (handle, _) = fs.open(ctx(), entry.inode, false, 0).unwrap();
    let mut writer = MockWriter::new();
    fs.read(
        ctx(),
        entry.inode,
        handle.unwrap(),
        &mut writer,
        16,
        0,
        None,
        0,
    )
    .unwrap();
    assert_eq!(writer.buf, b"hello");
}
