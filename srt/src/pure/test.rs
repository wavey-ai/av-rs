//! Tests of the pure Rust backend's API surface (blocking and tokio).

use crate::*;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

#[test]
fn options_map_to_config() {
    let cfg = listener_config(vec![
        ListenerOption::TimestampBasedPacketDeliveryMode(false),
        ListenerOption::TooLatePacketDrop(false),
        ListenerOption::ReceiveBufferSize(36_400_000),
        ListenerOption::SendBufferSize(36_400_000),
        ListenerOption::PeerLatency(250),
    ])
    .unwrap();
    assert!(!cfg.tsbpd);
    assert!(!cfg.tlpktdrop);
    assert_eq!(cfg.rcv_buf_pkts, 36_400_000 / 1472);
    assert_eq!(cfg.snd_buf_pkts, 36_400_000 / 1472);
    assert_eq!(cfg.peer_latency_ms, 250);
    assert_eq!(cfg.rcv_latency_ms, 120);
    assert!(listener_config(vec![ListenerOption::PeerLatency(-1)]).is_err());

    let cfg = connect_config(&ConnectOptions {
        stream_id: Some("#!::r=live/test,m=publish".into()),
        max_bandwidth: Some(MaxBandwidth::Relative {
            input_bandwidth: 1_000_000,
            overhead_bandwidth_percentage: 30,
        }),
        max_send_payload_size: Some(1400),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(cfg.stream_id.as_deref(), Some("#!::r=live/test,m=publish"));
    assert_eq!((cfg.max_bw, cfg.input_bw, cfg.overhead_bw_pct), (0, 1_000_000, 30));
    assert_eq!(cfg.payload_size, 1400);
    assert_eq!(cfg.connect_timeout, Duration::from_secs(3));
    let cfg = connect_config(&ConnectOptions {
        max_bandwidth: Some(MaxBandwidth::Infinite),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(cfg.max_bw, -1);
    let cfg = connect_config(&ConnectOptions {
        max_bandwidth: Some(MaxBandwidth::Absolute(5_000_000)),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(cfg.max_bw, 5_000_000);
    assert!(connect_config(&ConnectOptions {
        max_send_payload_size: Some(1457),
        ..Default::default()
    })
    .is_err());
    assert!(connect_config(&ConnectOptions {
        stream_id: Some("x".repeat(513)),
        ..Default::default()
    })
    .is_err());
}

#[test]
fn passphrase_maps_to_config() {
    let cfg = connect_config(&ConnectOptions {
        passphrase: Some("thepassphrase".into()),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(cfg.passphrase.as_deref(), Some("thepassphrase"));
    // libsrt accepts 10..=79 characters
    assert!(connect_config(&ConnectOptions {
        passphrase: Some("short".into()),
        ..Default::default()
    })
    .is_err());
}

#[test]
fn blocking_client_server() {
    let port = free_port();
    let listener = Listener::bind(("127.0.0.1", port)).unwrap();
    let t = std::thread::spawn(move || {
        let (mut s, peer) = listener.accept().unwrap();
        assert_eq!(s.id().map(String::as_str), Some("blocking"));
        let mut buf = [0u8; 1316];
        let mut got = Vec::new();
        for _ in 0..100 {
            let n = s.read(&mut buf).unwrap();
            got.push(buf[..n].to_vec());
        }
        (got, peer)
    });
    let mut c = Stream::connect(
        ("127.0.0.1", port),
        &ConnectOptions {
            stream_id: Some("blocking".into()),
            ..Default::default()
        },
    )
    .unwrap();
    for i in 0..100u8 {
        assert_eq!(c.write(&[i; 1316]).unwrap(), 1316);
    }
    let (got, peer) = t.join().unwrap();
    assert_eq!(peer.ip().to_string(), "127.0.0.1");
    for (i, m) in got.iter().enumerate() {
        assert_eq!(m.len(), 1316);
        assert!(m.iter().all(|&b| b == i as u8));
    }
    assert!(c.stats().map_or(true, |s| s.pkt_sent >= 100 || s.pkt_sent == 0));
}

#[cfg(feature = "async")]
mod async_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::join;

    static DEFAULT: ConnectOptions = ConnectOptions {
        passphrase: None,
        stream_id: None,
        timestamp_based_packet_delivery_mode: None,
        too_late_packet_drop: None,
        receive_buffer_size: None,
        send_buffer_size: None,
        max_bandwidth: None,
        max_send_payload_size: None,
    };

    #[tokio::test]
    async fn test_async_client_server() {
        let port = free_port();
        let listener = AsyncListener::bind_with_options(
            ("127.0.0.1", port),
            [
                ListenerOption::TimestampBasedPacketDeliveryMode(false),
                ListenerOption::TooLatePacketDrop(false),
                ListenerOption::ReceiveBufferSize(36400000),
            ]
            .iter()
            .cloned(),
        )
        .unwrap();

        let options = ConnectOptions {
            timestamp_based_packet_delivery_mode: Some(false),
            too_late_packet_drop: Some(false),
            max_send_payload_size: Some(1400),
            ..Default::default()
        };
        let (accept_result, connect_result) = join!(listener.accept(), AsyncStream::connect(("127.0.0.1", port), &options));
        let mut server_conn = accept_result.unwrap().0;
        let mut client_conn = connect_result.unwrap();
        assert_eq!(client_conn.id(), None);
        assert_eq!(server_conn.id(), None);

        let mut buf = [0; 1316];
        for i in 0..5 {
            let payload = [i as u8; 1316];
            for _ in 0..10 {
                assert_eq!(client_conn.write(&payload).await.unwrap(), 1316);
            }
            for _ in 0..10 {
                assert_eq!(server_conn.read(&mut buf).await.unwrap(), 1316);
                assert_eq!(&buf, &payload);
            }
        }

        // one message per write, cut at the payload size (as the libsrt backend)
        let big = [7u8; 1500];
        assert_eq!(client_conn.write(&big[..]).await.unwrap(), 1400);
        let mut rbuf = [0u8; 2000];
        assert_eq!(server_conn.read(&mut rbuf).await.unwrap(), 1400);

        // the listener side can answer (product: response body)
        server_conn.write_all(b"response").await.unwrap();
        let n = client_conn.read(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..n], b"response");

        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(server_conn.stats().unwrap().pkt_recv > 0);
    }

    #[tokio::test]
    async fn test_async_client_server_disconnect() {
        let port = free_port();
        let listener = AsyncListener::bind(("127.0.0.1", port)).unwrap();
        let options = Default::default();
        let (accept_result, connect_result) = join!(listener.accept(), AsyncStream::connect(("127.0.0.1", port), &options));
        let mut server_conn = accept_result.unwrap().0;
        let client_conn = connect_result.unwrap();
        assert_eq!(client_conn.id(), None);

        drop(client_conn);

        // the read fails with libsrt's "connection lost" text, which the
        // product matches
        let mut buf = [0; 1316];
        let e = tokio::time::timeout(Duration::from_secs(2), server_conn.read(&mut buf))
            .await
            .expect("read returns at once")
            .unwrap_err();
        assert!(e.to_string().contains("srt_recv error: 2001"), "{}", e);
        assert_eq!(e.to_string(), "srt_recv error: 2001 (errno = 0)");
        assert_eq!(server_conn.close_reason(), Some(srt_core::CloseReason::PeerShutdown));
        let e = server_conn.write(b"x").await.unwrap_err();
        assert!(e.to_string().contains("srt_send error: 2001"), "{}", e);
    }

    #[tokio::test]
    async fn test_async_data_before_close_is_delivered() {
        let port = free_port();
        let listener = AsyncListener::bind_with_options(
            ("127.0.0.1", port),
            [ListenerOption::TimestampBasedPacketDeliveryMode(true), ListenerOption::PeerLatency(120)],
        )
        .unwrap();
        let (a, c) = join!(listener.accept(), AsyncStream::connect(("127.0.0.1", port), &DEFAULT));
        let mut server = a.unwrap().0;
        let mut client = c.unwrap();
        for i in 0..50u8 {
            client.write_all(&[i; 188 * 7]).await.unwrap();
        }
        // close right away: the receiver still holds most of it for TSBPD
        drop(client);
        let mut buf = [0u8; 1316];
        let mut n = 0;
        loop {
            match tokio::time::timeout(Duration::from_secs(3), server.read(&mut buf)).await.unwrap() {
                Ok(len) => {
                    assert_eq!(len, 1316);
                    assert!(buf.iter().all(|&b| b == n as u8));
                    n += 1;
                }
                Err(e) => {
                    assert!(e.to_string().contains("srt_recv error: 2001"));
                    break;
                }
            }
        }
        assert_eq!(n, 50);
    }

    #[tokio::test]
    async fn test_async_callback_stream_id_and_deny() {
        let port = free_port();
        let listener = AsyncListener::bind(("127.0.0.1", port))
            .unwrap()
            .with_callback(|stream_id: Option<&str>| match stream_id {
                Some("#!::r=live/test,m=publish") => ListenerCallbackAction::Allow { passphrase: None },
                _ => ListenerCallbackAction::Deny,
            })
            .unwrap();

        // denied: the caller sees a rejection (1002), quickly
        let t0 = Instant::now();
        let e = AsyncStream::connect(
            ("127.0.0.1", port),
            &ConnectOptions {
                stream_id: Some("other".into()),
                ..Default::default()
            },
        )
        .await
        .err()
        .expect("denied");
        assert_eq!(e.to_string(), "srt_connect error: 1002 (errno = 0)");
        assert!(t0.elapsed() < Duration::from_secs(2));

        let options = ConnectOptions {
            stream_id: Some("#!::r=live/test,m=publish".into()),
            ..Default::default()
        };
        let (a, c) = join!(listener.accept(), AsyncStream::connect(("127.0.0.1", port), &options));
        let (server, peer) = a.unwrap();
        let client = c.unwrap();
        assert_eq!(server.id().map(String::as_str), Some("#!::r=live/test,m=publish"));
        assert_eq!(client.id(), options.stream_id.as_ref());
        assert_eq!(peer.ip().to_string(), "127.0.0.1");
        assert_eq!(server.peer_addr(), peer);
    }

    #[tokio::test]
    async fn test_async_passphrase() {
        // the libsrt backend's test, unchanged
        let port = free_port();
        let listener = AsyncListener::bind_with_options(("127.0.0.1", port), [ListenerOption::TooLatePacketDrop(false)].iter().cloned())
            .unwrap()
            .with_callback(|stream_id: Option<&_>| {
                assert_eq!(stream_id, Some("mystreamid"));
                ListenerCallbackAction::Allow {
                    passphrase: Some("thepassphrase".to_string()),
                }
            })
            .unwrap();

        let mut options = ConnectOptions {
            passphrase: Some("notthepassphrase".to_string()),
            stream_id: Some("mystreamid".to_string()),
            ..Default::default()
        };

        assert!(AsyncStream::connect(("127.0.0.1", port), &options).await.is_err());

        options.passphrase = Some("thepassphrase".to_string());
        let (accept_result, connect_result) = join!(listener.accept(), AsyncStream::connect(("127.0.0.1", port), &options));
        let mut server_conn = accept_result.unwrap().0;
        let mut client_conn = connect_result.unwrap();
        assert_eq!(client_conn.id(), options.stream_id.as_ref());

        assert_eq!(client_conn.write(b"foo").await.unwrap(), 3);

        let mut buf = [0; 1316];
        assert_eq!(server_conn.read(&mut buf).await.unwrap(), 3);
        assert_eq!(&buf[0..3], b"foo");
    }

    #[tokio::test]
    async fn test_async_passphrase_mismatch_is_never_clear() {
        let port = free_port();
        let listener = AsyncListener::bind(("127.0.0.1", port))
            .unwrap()
            .with_callback(|_: Option<&_>| ListenerCallbackAction::Allow {
                passphrase: Some("thepassphrase".to_string()),
            })
            .unwrap();
        // a caller without a passphrase is rejected, never connected in clear
        let e = AsyncStream::connect(("127.0.0.1", port), &ConnectOptions::default()).await.err().expect("rejected");
        assert_eq!(e.to_string(), "srt_connect error: 1002 (errno = 0)");
        // and a caller with one, against a listener without
        let port2 = free_port();
        let _plain = AsyncListener::bind(("127.0.0.1", port2)).unwrap();
        let options = ConnectOptions {
            passphrase: Some("thepassphrase".to_string()),
            ..Default::default()
        };
        assert!(AsyncStream::connect(("127.0.0.1", port2), &options).await.is_err());
        drop(listener);
    }

    #[tokio::test]
    async fn test_async_connect_timeout() {
        // nothing listens: libsrt's "no server" after the connect timeout
        let port = free_port();
        let t0 = Instant::now();
        let e = AsyncStream::connect(("127.0.0.1", port), &ConnectOptions::default()).await.err().expect("no server");
        assert_eq!(e.to_string(), "srt_connect error: 1001 (errno = 0)");
        assert!(t0.elapsed() >= Duration::from_secs(2) && t0.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_async_write_backpressure_and_throughput() {
        // a slow reader: the writer must block, nothing is lost, order kept
        let port = free_port();
        let listener = AsyncListener::bind_with_options(
            ("127.0.0.1", port),
            [
                ListenerOption::TimestampBasedPacketDeliveryMode(false),
                ListenerOption::TooLatePacketDrop(false),
                ListenerOption::ReceiveBufferSize(1472 * 256),
            ],
        )
        .unwrap();
        let options = ConnectOptions {
            timestamp_based_packet_delivery_mode: Some(false),
            too_late_packet_drop: Some(false),
            send_buffer_size: Some(1472 * 256),
            max_bandwidth: Some(MaxBandwidth::Infinite),
            ..Default::default()
        };
        let (a, c) = join!(listener.accept(), AsyncStream::connect(("127.0.0.1", port), &options));
        let mut server = a.unwrap().0;
        let mut client = c.unwrap();
        const N: u32 = 20_000;
        let writer = tokio::spawn(async move {
            let mut m = [0u8; 1316];
            for i in 0..N {
                m[..4].copy_from_slice(&i.to_be_bytes());
                client.write_all(&m).await.unwrap();
            }
            client
        });
        let mut buf = [0u8; 1316];
        for i in 0..N {
            if i % 2000 == 0 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let n = server.read(&mut buf).await.unwrap();
            assert_eq!(n, 1316);
            assert_eq!(u32::from_be_bytes(buf[..4].try_into().unwrap()), i);
        }
        let client = writer.await.unwrap();
        drop(client);
    }

    #[tokio::test]
    async fn test_listener_drop_keeps_accepted_streams() {
        let port = free_port();
        let listener = AsyncListener::bind(("127.0.0.1", port)).unwrap();
        let (a, c) = join!(listener.accept(), AsyncStream::connect(("127.0.0.1", port), &DEFAULT));
        let mut server = a.unwrap().0;
        let mut client = c.unwrap();
        drop(listener);
        client.write_all(b"after listener drop").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(2), server.read(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"after listener drop");
        // new callers are not accepted any more
        assert!(AsyncStream::connect(("127.0.0.1", port), &ConnectOptions::default()).await.is_err());
    }

    #[tokio::test]
    async fn test_accept_is_cancel_safe() {
        let port = free_port();
        let listener = AsyncListener::bind(("127.0.0.1", port)).unwrap();
        // an accept dropped before anyone connects loses nothing
        assert!(tokio::time::timeout(Duration::from_millis(50), listener.accept()).await.is_err());
        let (a, c) = join!(listener.accept(), AsyncStream::connect(("127.0.0.1", port), &DEFAULT));
        assert!(a.is_ok() && c.is_ok());
    }
}
