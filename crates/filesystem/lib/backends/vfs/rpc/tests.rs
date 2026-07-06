//! End-to-end RPC tests: a [`VirtualFs`] whose provider lives behind a socket,
//! answered by [`serve_unix`] running the in-process [`InMemoryFs`] reference.
//! This proves the RPC path behaves identically to a direct in-process provider.

#![cfg(test)]

use std::ffi::CString;
use std::sync::Arc;
use std::thread::JoinHandle;

use super::super::VirtualFs;
use super::super::test_backend::{InMemoryFs, LINUX_ENOENT, MockReader, MockWriter};
use super::protocol::{VfsRequest, VfsResponse};
use super::{MountStream, RpcPathFs, SocketTransport, dispatch, serve_unix, unix_socket_backend};
use crate::{Context, DynFileSystem, Extensions, PathFs, SetattrValid};
use serde_bytes::ByteBuf;

const ROOT: u64 = 1;

type MountedFs = VirtualFs<RpcPathFs<SocketTransport<MountStream>>>;

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

/// The errno of a result that is expected to be an error (the `Ok` type need not
/// be `Debug`, unlike `Result::unwrap_err`).
fn err_no<T>(r: std::io::Result<T>) -> Option<i32> {
    r.err().expect("expected an error").raw_os_error()
}

/// Spin up a serve loop over a socketpair and return the mounted VirtualFs plus
/// the serve thread handle. Dropping the VirtualFs closes the client end, which
/// makes `serve_unix` return `Ok(())` so the thread can be joined.
fn mount() -> (MountedFs, JoinHandle<()>) {
    let (client, server) = MountStream::pair().unwrap();
    let provider: Arc<dyn PathFs> = Arc::new(InMemoryFs::new());
    let serve = std::thread::spawn(move || {
        serve_unix(server, provider).expect("serve_unix");
    });
    let fs = unix_socket_backend(client).expect("mount");
    (fs, serve)
}

fn create_file(fs: &MountedFs, name: &str) -> (u64, u64) {
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

#[test]
fn rpc_create_write_read_round_trips() {
    let (fs, serve) = mount();
    let (ino, handle) = create_file(&fs, "hello.txt");

    let payload = b"data over the wire";
    let mut reader = MockReader::new(payload.to_vec());
    let n = fs
        .write(
            ctx(),
            ino,
            handle,
            &mut reader,
            payload.len() as u32,
            0,
            None,
            false,
            false,
            0,
        )
        .unwrap();
    assert_eq!(n, payload.len());

    let mut writer = MockWriter::new();
    fs.read(ctx(), ino, handle, &mut writer, 64, 0, None, 0)
        .unwrap();
    assert_eq!(writer.buf, payload);

    let (st, _) = fs.getattr(ctx(), ino, None).unwrap();
    assert_eq!(st.st_size as usize, payload.len());

    drop(fs);
    serve.join().unwrap();
}

#[test]
fn rpc_mkdir_readdir_rename_unlink() {
    let (fs, serve) = mount();

    fs.mkdir(ctx(), ROOT, &cstr("dir"), 0o755, 0, Extensions::default())
        .unwrap();
    let dir = fs.lookup(ctx(), ROOT, &cstr("dir")).unwrap();
    fs.create(
        ctx(),
        dir.inode,
        &cstr("a.txt"),
        0o644,
        false,
        0,
        0,
        Extensions::default(),
    )
    .unwrap();

    let (h, _) = fs.opendir(ctx(), dir.inode, 0).unwrap();
    let entries = fs.readdir(ctx(), dir.inode, h.unwrap(), 4096, 0).unwrap();
    let names: Vec<&[u8]> = entries.iter().map(|e| e.name).collect();
    assert!(names.contains(&b"a.txt".as_slice()));

    fs.rename(ctx(), dir.inode, &cstr("a.txt"), ROOT, &cstr("b.txt"), 0)
        .unwrap();
    assert!(fs.lookup(ctx(), ROOT, &cstr("b.txt")).is_ok());

    fs.unlink(ctx(), ROOT, &cstr("b.txt")).unwrap();
    assert_eq!(
        err_no(fs.lookup(ctx(), ROOT, &cstr("b.txt"))),
        Some(LINUX_ENOENT)
    );

    drop(fs);
    serve.join().unwrap();
}

#[test]
fn rpc_setattr_truncate_and_statfs() {
    let (fs, serve) = mount();
    let (ino, handle) = create_file(&fs, "t.txt");
    let mut reader = MockReader::new(b"0123456789".to_vec());
    fs.write(
        ctx(),
        ino,
        handle,
        &mut reader,
        10,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();

    let mut st: crate::stat64 = unsafe { std::mem::zeroed() };
    st.st_size = 4;
    let (new, _) = fs
        .setattr(ctx(), ino, st, None, SetattrValid::SIZE)
        .unwrap();
    assert_eq!(new.st_size, 4);

    let stat = fs.statfs(ctx(), ROOT).unwrap();
    assert_eq!(stat.f_namemax, 255);

    drop(fs);
    serve.join().unwrap();
}

#[test]
fn rpc_rmdir_nonempty_returns_enotempty_wire() {
    let (fs, serve) = mount();
    fs.mkdir(ctx(), ROOT, &cstr("d"), 0o755, 0, Extensions::default())
        .unwrap();
    let d = fs.lookup(ctx(), ROOT, &cstr("d")).unwrap();
    fs.create(
        ctx(),
        d.inode,
        &cstr("c"),
        0o644,
        false,
        0,
        0,
        Extensions::default(),
    )
    .unwrap();

    // The wire/guest speaks Linux errno; ENOTEMPTY is 39. The macOS dispatch
    // errno mapping must pass this through unchanged rather than collapse it to
    // EIO (which it did when the pass-through guard was incomplete).
    assert_eq!(err_no(fs.rmdir(ctx(), ROOT, &cstr("d"))), Some(39));

    drop(fs);
    serve.join().unwrap();
}

#[test]
fn rpc_xattr_round_trips() {
    let (fs, serve) = mount();
    let (ino, _) = create_file(&fs, "x.txt");
    fs.setxattr(ctx(), ino, &cstr("user.k"), b"v", 0).unwrap();
    match fs.getxattr(ctx(), ino, &cstr("user.k"), 64).unwrap() {
        crate::GetxattrReply::Value(v) => assert_eq!(v, b"v"),
        _ => panic!("unexpected getxattr reply"),
    }
    drop(fs);
    serve.join().unwrap();
}

#[test]
fn dispatch_translates_provider_errors_to_wire_errno() {
    let provider = InMemoryFs::new();
    let resp = dispatch(
        &provider,
        VfsRequest::GetAttr {
            path: ByteBuf::from(b"/missing".to_vec()),
        },
    );
    // ENOENT == 2 on both host and the Linux wire, so this is stable cross-platform.
    assert!(matches!(resp, VfsResponse::Err(2)));
}

#[test]
fn dispatch_rejects_relative_path() {
    let provider = InMemoryFs::new();
    let resp = dispatch(
        &provider,
        VfsRequest::GetAttr {
            path: ByteBuf::from(b"relative".to_vec()),
        },
    );
    assert!(matches!(resp, VfsResponse::Err(_)));
}

#[test]
fn dispatch_getattr_many_reports_per_path_errors() {
    let provider = InMemoryFs::new();
    provider
        .create(b"/here", &super::super::VAttr::file(0o644, 0))
        .unwrap();
    let resp = dispatch(
        &provider,
        VfsRequest::GetAttrMany {
            paths: vec![
                ByteBuf::from(b"/here".to_vec()),
                ByteBuf::from(b"/gone".to_vec()),
            ],
        },
    );
    match resp {
        VfsResponse::AttrMany(results) => {
            assert!(matches!(results[0], super::protocol::VAttrResult::Ok(_)));
            assert!(matches!(results[1], super::protocol::VAttrResult::Err(2)));
        }
        other => panic!("unexpected: {other:?}"),
    }
}
