# Source and dependency notices

Application UI, icon, store, native bridge and some boundary tests were adapted
from ArcCal/masque-vpn (Masque NF), and protocol parsers were copied from
ArcCal/network-relay at the revisions in ORIGIN-PROVENANCE.json. These are
independent copies made at the owner's request; this repository does not consume
those repositories as build dependencies or modify their product code.

This copy does not grant a new license for ArcCal-owned application code.
Third-party components retain their own licenses.

The vendored hyperium/h3 implementation retains its upstream MIT license at
Core/vendor/h3/LICENSE. Its inherited local changes are recorded in
Core/vendor/h3/PATCH.md. Cargo.lock identifies external dependency versions;
their licenses continue to apply. Quinn and rustls appear only in development
and test dependencies, never as the app's production transport.
