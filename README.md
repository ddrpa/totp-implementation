# Time-based One-Time Password (TOTP) algorithm implementation in Java

基于时间的一次性密码算法（TOTP）Java 实现，同时支持解析 Google Authenticator 导出的二维码。

## 添加依赖

本项目制品通过 sonatype.org 同步到 Maven
中央仓库，可以访问 [MvnRepository](https://mvnrepository.com/artifact/cc.ddrpa.security/totp)
获取最新的正式版本。

```xml
<dependency>
    <groupId>cc.ddrpa.security</groupId>
    <artifactId>totp</artifactId>
    <version>${totp.version}</version>
</dependency>
```

预览版本可以在添加 snapshots
源后通过 [sonatype.org](https://s01.oss.sonatype.org/#nexus-search;quick~cc.ddrpa)
查找最新版本。

```xml

<repositories>
  <repository>
    <id>snapshots</id>
    <url>https://s01.oss.sonatype.org/content/repositories/snapshots/</url>
  </repository>
</repositories>
```

## 使用方法

创建随机密钥和 URI：

```java
String secret = Authenticator.generateSecret();
String uri = Authenticator.generateQRCode(secret, "ddrpa.cc", "yufan@live.com");
```

使用 URI 创建二维码，使用 Google Authenticator / Microsoft Authenticator / FreeOTP Authenticator 扫描二维码并添加账户。 
也可以手动输入密钥和账户信息。

输入两步验证器显示的数字进行验证：

```java
assertTrue(Authenticator.verifyCode(secret, CODE_FROM_AUTHENTICATOR));
```

若客户端与服务端有不可避免的时间偏移量，添加时间窗口参数：

```java
assertTrue(Authenticator.verifyCode(secret, CODE_FROM_AUTHENTICATOR, Authenticator.DEFAULT_TIME_STEP_IN_SECONDS, 1));
```

时间偏差在一个时间段内的验证码也可被接受。

## 解析 Google Authenticator 导出的二维码

`cc.ddrpa.security.totp.migrate.GoogleAuthenticatorMigrator` 类提供了解析 Google Authenticator 导出二维码的方法。
