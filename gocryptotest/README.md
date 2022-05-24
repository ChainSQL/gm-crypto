# 联合测试国密标准库和三方包改造

# 前提条件

需要安装go1.17.8 的国密标准库

# 联合测试

```bash
cd gm-crypto/gmcryptotest/
#启动国密标准库和三方包国密server
go test -v -test.run TestTLSServer
#另开窗口，启动国密标准库和三方包国密client
go test -v -test.run TestTLSClient
```

