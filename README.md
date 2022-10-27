# wgfwder
Simple utility that asks as a wireguard endpoint and forwards select packets into a tunnel

## Questions?

Why is wireguard-go a submodule rather than just a package in go.mod?
This is an unresolved issue where `go build` fails with `gvisor.dev/gvisor@v0.0.0-20221026044613-c1427a04dfba/pkg/bits/uint64_arch.go:35:9: undefined: MaskOf64` if the wireguard-go package is used. It builds correct if wireguard-go is a submodule. The issue appears to be caused by the import `golang.zx2c4.com/wireguard/tun/netstack`. Given that `undefined: MaskOf64` yields zero google search results a low-effort solution is not forth coming.

