# Evidence identity

The application is now named **Network Relay NF**, under `network-relay-nf/`.
Earlier native log excerpts retain the misspelled application, executable and
Rust module names exactly as recorded. These historical labels do not name a
separate application.

Raw log files, upload hashes, source revisions and historical test-result hashes
are preserved. A source rename does not establish that the earlier tests ran
against the renamed build. In particular,
[native-quic-20261011.json](native-quic-20261011.json) records the checksum of the
unchanged [native log excerpt](native-quic-20261011.log), and
[interop-results.json](interop-results.json) identifies the sources tested at
the time of that run.
