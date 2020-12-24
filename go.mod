module github.com/peersafe/gm-crypto

go 1.14

require (
	github.com/golang/protobuf v1.4.3
	golang.org/x/crypto v0.0.0-20200709230013-948cd5f35899
	golang.org/x/net v0.0.0-20190404232315-eb5bcb51f2a3
	golang.org/x/sys v0.0.0-20190412213103-97732733099d
	google.golang.org/genproto v0.0.0-20190819201941-24fa4b261c55
	google.golang.org/grpc v1.34.0
	github.com/peersafe/gm-crypto v0.0.0
)

replace google.golang.org/grpc v1.34.0 => google.golang.org/grpc v1.29.1
replace github.com/peersafe/gm-crypto v0.0.0 => gitlab.peersafe.cn/fabric/gm-crypto v1.0.1-0.20201223091419-2a6aec192d58
