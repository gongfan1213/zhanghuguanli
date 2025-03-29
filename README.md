# 第17章 账户管理系统实战
#### 17.1 启动一个简单的RESTful服务器
第15章我们学习了Gin框架的基本操作，下面就来看看如何把Gin框架应用到企业开发中。
```go
// Main.go
func main() {
    G := gin.New()
    middlewares := []gin.HandlerFunc{}
    router.Load(
        g,
        middlewares...,
    )

    go func() {
        if err := checkServer(); err != nil {
            log.Fatal("自检程序发生错误...", err)
        }
        log.Print("路由成功部署.")
    }()

    log.Printf("开始监听http地址: %s", "9090")
    log.Printf(http.ListenAndServe(":9090", g).Error())
}

func checkServer() error {
    for i := 0; i < 10; i++ {
        //发送一个GET请求给 /check/health，验证服务器是否成功
        resp, err := http.Get("http://127.0.0.1:9090/check/health")
        if err == nil && resp.StatusCode == 200 {
            return nil
        }

        // Sleep 1 second 继续重试
        log.Print("等待路由，1秒后重试.")
        time.Sleep(time.Second)
    }
    return errors.New("无法连接到路由.")
}
```
1. **加载路由**
   
main函数通过调用router.Load函数来加载路由：
```go
func Load(engine *gin.Engine, middlewares ...gin.HandlerFunc) *gin.Engine {
    engine.Use(gin.Recovery())
    engine.Use(middlewares...)
    engine.NoRoute(func(context *gin.Context) {
        context.String(http.StatusNotFound, "API路由不正确.")
    })
    check := engine.Group("/check")
    {
        check.GET("/health", health.Health)
    }
    return engine
}
```
该代码块定义了一个叫作check的分组，在该分组下注册了/health HTTP路径，并路由到health.Health函数。

check分组主要用来检查API Server的健康状况：
```go
// Health 输出“OK”，表示可以访问
func Health(c *gin.Context) {
    message := "OK"
    c.String(http.StatusOK, "\n"+message)
}
```
源代码文件Chapter17/17 - 1：

（1）输入命令go build，生成一个二进制文件17 - 1。

（2）运行二进制文件17 - 1。
```
[GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
 - using env:	export GIN_MODE=release
 - using code:	gin.SetMode(gin.ReleaseMode)
[GIN-debug] GET    /check/health         --> github.com/i-coder-robot/book_final_code/Chapter16/health.Health (2 handlers)
2021/03/08 10:04:52 开始监听http地址: 9090
2021/03/08 10:04:52 路由成功部署.
```
可以看到监听到了9090端口，路由成功部署。

在浏览器中输入http://127.0.0.1:9090/check/health，发送HTTP GET请求，如果函数正确执行，并且返回的HTTP StatusCode为200，则页面输出“OK”。/check /health路径会匹配到health/health.go中的Health函数，该函数只返回一个字符串：OK。

本节通过一个例子快速启动了一个API服务器，以此介绍Go API的开发流程，在后面的章节中，将讲解如何一步步构建一个企业级的API服务器。

#### 17.2 Viper
在日常开发中，变更配置文件是十分常见的，因为在不同的环境中，如开发环境、测试环境、预发布环境和生产环境等，配置文件的内容是不同的。在企业级开发中，大多使用Viper进行配置。

**Viper简介**
Viper是开源的Go语言配置工具，它具有如下特性：

（1）可以设置默认值。

（2）可以读取多种格式的配置文件，如JSON、TOML、YAML、HCL等。

（3）可以监控配置文件改动，并热加载配置文件。

（4）可以从远程配置中心读取配置（etcd/consul），并监控变动。

（5）可以从命令行flag读取配置。

（6）可以从缓存中读取配置。

（7）支持直接设置配置项的值。

Viper不仅功能非常强大，而且用起来十分方便，在初始化配置文件后，读取配置只需要调用viper.GetString、viper.GetInt和viper.GetBool等函数即可。

```yaml
# config.yaml
runmode: debug  # 开发模式有debug模式、release模式和test模式三种
addr: :909      # HTTP绑定端口
url: http://127.0.0.1:9090  # pingServer函数请求API服务器的ip:port
max_check_count: 10  # pingServer函数尝试的次数
database:
    name: db
    addr: 127.0.0.1:3306
    username: root
    password: 123456
```

如果要读取username配置，则执行viper.GetString("database.username")即可。这里采用了YAML格式的配置文件，因为它包含的内容更丰富，可读性更强。

打开源代码文件17 - 2/main.go：

```go
var (
    cfg = flag.String("config", "c", "")
)
func main() {
    flag.Parse()

    // init config
    if err := config.Init(*cfg); err != nil {
        panic(err)
    }
    gin.SetMode(viper.GetString("runmode"))
    G := gin.New()
    middlewares := []gin.HandlerFunc{}
    router.Load(
        g,
        middlewares...,
    )

    go func() {
        if err := checkServer(); err != nil {
            log.Fatal("自检程序发生错误...", err)
        }
        log.Print("路由成功部署.")
    }()
    port := viper.GetString("addr")
    log.Printf("开始监听HTTP地址%s", port)
    log.Printf(http.ListenAndServe(port, g).Error())
}

func checkServer() error {
    max := viper.GetInt("max_check_count")
    for i := 0; i < max; i++ {
        //发送一个GET请求给 "/check/health"，验证服务器是否成功
        url := viper.GetString("url") + "/check/health"
        resp, err := http.Get(url)
        if err == nil && resp.StatusCode == 200 {
            return nil
        }

        log.Print("等待路由，1秒后重试.")
        time.Sleep(time.Second)
    }
    return errors.New("无法连接到路由.")
}
```

在main函数中增加了config.Init(*cfg)调用，用来初始化配置。cfg变量值是从命令行flag传入的，既可以传值，比如传入/17 - 2 - c config.yaml，也可以为空。如果为空，则默认读取conf/config.yaml。
1. **解析配置**
   
main函数通过config.Init函数来解析并配置文件（conf/config.yaml）。

打开源代码文件17 - 2/config/config.go：
```go
type Config struct {
    Name string
}

func Init(name string) error {
    c := Config {
        Name: name,
    }

    //初始化配置文件
    if err := c.initConfig(); err != nil {
        return err
    }

    //监控配置文件变化并热加载程序
    c.watchConfig()

    return nil
}

func (c *Config) initConfig() error {
    if c.Name != "" {
        viper.SetConfigFile(c.Name) //如果指定了配置文件，则解析指定的配置文件
    } else {
        viper.AddConfigPath("conf") //如果没有指定配置文件，则解析默认的配置文件
        viper.SetConfigName("config")
    }
    viper.SetConfigType("yaml") //设置配置文件格式为YAML
    if err := viper.ReadInConfig(); err != nil { // 用Viper解析配置文件
        return err
    }
    return nil
}

//监控配置文件变化并热加载程序
func (c *Config) watchConfig() {
    viper.WatchConfig()
    viper.OnConfigChange(func(e fsnotify.Event) {
        log.Printf("Config file changed: %s", e.Name)
    })
}
```

config.Init函数通过initConfig函数解析配置文件，达到初始化的目的。当配置文件发生变化时，打印日志。注意，除打印日志外，也可以根据实际需求进行其他逻辑处理。

两个函数解析如下。

**[1] func (c *Config) initConfig() error**
设置并解析配置文件。如果指定了配置文件*cfg，则解析指定的配置文件，否则解析默认的配置文件conf/config.yaml。通过指定配置文件可连接不同的环境（开发环境、测试环境、预发布环境、生产环境）并加载不同的配置，可以方便地开发和测试不同环境之间的部署。

设置如下：
```go
if c.Name != "" {
    viper.SetConfigFile(c.Name) //如果指定了配置文件，则解析指定的配置文件
} else {
    viper.AddConfigPath("conf") //如果没有指定配置文件，则解析默认的配置文件
    viper.SetConfigName("config")
}
```
这样，config.Init函数中的viper.ReadInConfig函数即可最终调用Viper来解析配置文件了。

**[2] func (c *Config) watchConfig()**

通过该函数的设置，可以让Viper监控配置文件的变更。如果有变更，则热更新程序。

注意：热更新是指在不重启API进程的情况下，让API加载最新配置项的值。

一般来说，更改配置文件是需要重启API的，即让程序重新加载最新的配置文件，而这在生产级环境中是不可取的。

如果使用Viper，则只要更改了配置，程序就可以自动识别最新配置项，是不是很方便呢？ 


### 2. 读取配置项
API服务器端口号经常需要变更，除此之外，API需要根据不同的模式（开发模式、生产模式、测试模式）来匹配不同的行为。开发模式要求是可配置的，而这些都可以在配置文件中进行配置。

新建配置文件conf/config.yaml（默认配置文件名字为config.yaml），config.yaml中的内容如下：

```yaml
runmode: debug  # 开发模式有debug模式、release模式和test模式
addr: :9090  # 用HTTP绑定端口
url: http://127.0.0.1:9090  # pingServer函数请求API服务器端口号ip:port
max_check_count: 10  # pingServer函数尝试的次数
database:
    name: db
    addr: 127.0.0.1:3306
    username: root
    password: 123456
```

在Gin中有三种开发模式，分别为debug模式、release模式和test模式。

在日常开发中通常使用的是debug模式，在这种模式下会打印很多debug信息，有利于我们排查错误。

如果发布到生产环境，则使用release模式。

本节的源代码在Chapter17/17 - 2文件中。

（1）输入命令go build命令，生成一个二进制文件17 - 2。

（2）运行二进制文件17 - 2：
```
a@adeiMac 17-2 %./17-2
[GIN-debug] [WARNING] Running in "debug" mode. Switch to "release" mode in production.
 - using env:	export GIN_MODE=release
 - using code:	gin.SetMode(gin.ReleaseMode)
[GIN-debug] GET    /check/health         --> github.com/i-coder-robot/book_final_code/Chapter16/health.Health (2 handlers)
2020/11/12 21:53:22 开始监听HTTP地址:9090
2020/11/12 21:53:22 路由成功部署.
```
可以看到，在用Viper读取配置文件之后，程序变得更加灵活，并且和原来启动是一样的。

### 17.3 日志追踪

本节介绍一款大名鼎鼎的Go语言的日志包——Zap，它的优点如下：

（1）能够将事件记录到文件中，而不是应用程序控制台。

（2）能够根据文件大小、时间或间隔等来切割日志文件。

（3）支持不同的日志级别，如INFO、DEBUG、ERROR等。

（4）能够打印基本信息，如调用文件或函数名及行号、日志时间等。

1. **初始化日志包**
打开本节的源代码文件Chapter17/MyLog/MyLog.go，输入如下代码：
```go
var Log *zap.SugaredLogger

const (
    output_dir = "./logs/"
    out_path   = "app.MyLog"
    err_path   = "app.myer"
)

func init() {
    _, err := os.Stat(output_dir)
    if err != nil {
        if os.IsNotExist(err) {
            err := os.Mkdir(output_dir, os.ModePerm)
            if err != nil {
                fmt.Printf("创建目录失败![%v]\n", err)
            }
        }
    }
    // 设置一些基本日志格式
    encoder := zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
        MessageKey:   "msg",
        LevelKey:     "level",
        TimeKey:      "ts",
        //CallerKey:    "file",
        CallerKey:    "caller",
        StacktraceKey: "trace",
        LineEnding:   zapcore.DefaultLineEnding,
        EncodeLevel:  zapcore.LowercaseLevelEncoder,
        //EncodeLevel:  zapcore.CapitalLevelEncoder,
        EncodeCaller: zapcore.ShortCallerEncoder,
        EncodeTime: func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
            enc.AppendString(t.Format("2006-01-02 15:04:05"))
        },
        EncodeDuration: func(d time.Duration, enc zapcore.PrimitiveArrayEncoder) {
            enc.AppendInt64(int64(d) / 1000000)
        },
    })

    //实现两个判断日志等级的interface
    infoLevel := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
        return true
    })

    warnLevel := zap.LevelEnablerFunc(func(lvl zapcore.Level) bool {
        return lvl >= zapcore.WarnLevel
    })

    //获取Info、Warn等日志文件的io.Writer抽象
    infoHook_1 := os.Stdout
    infoHook_2 := getWriter(out_path)
    errorHook := getWriter(err_path)

    //创建具体的logger
    core := zapcore.NewTee(
        zapcore.NewCore(encoder, zapcore.AddSync(infoHook_1), infoLevel),
        zapcore.NewCore(encoder, zapcore.AddSync(infoHook_2), infoLevel),
        zapcore.NewCore(encoder, zapcore.AddSync(errorHook), warnLevel),
    )

    //需要传入zap.AddCaller()才会显示打日志点的文件名和行数
    logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
    Log = logger.Sugar()
    defer logger.Sync()
}

func getWriter(filename string) io.Writer {
    hook, err := rotatelogs.New(
        output_dir+filename+".%Y%m%d",
        rotatelogs.WithLinkName(filename),
        rotatelogs.WithMaxAge(time.Hour*24*7),
        rotatelogs.WithRotationTime(time.Hour*24),
    )
    if err != nil {
        panic(err)
    }
    return hook
}
```
encoder := zapcore.NewConsoleEncoder 这个方法会设置一些基本的日志格式。

获取info、warn等日志文件的io.Writer抽象getWriter()：
```go
infoHook_1 := os.Stdout
infoHook_2 := getWriter(out_path)
errorHook := getWriter(err_path)
```
通过New方法可以得到logger。

注意：需要传入zap.AddCaller()才会显示打日志点的文件名和行数。
```go
logger := zap.New(core, zap.AddCaller())
func getWriter(filename string) io.Writer {
    hook, err := rotatelogs.New(
        output_dir+filename+".%Y%m%d",
        rotatelogs.WithLinkName(filename),
        rotatelogs.WithMaxAge(time.Hour*24*7),
        rotatelogs.WithRotationTime(time.Hour*24),
    )
    if err != nil {
        panic(err)
    }
    return hook
}
```
这个方法会生成logger实际生成的文件名app.MyLog.YYmmddHH。app.Mylog是指向最日志的链接。该文件会保存7天内的日志，并且每小时（整点）分割一次日志。
2. **调用日志包**
调用下面的日志包：
```go
func main() {
    MyLog.Log.Info("Info日志开始")
    MyLog.Log.Error(" Eroor错误日志")
    MyLog.Log.Info("Info日志结束")
}
```
3. **查看日志文件**
程序执行到MyLog.Log.Error("Eroor错误日志")这一行时会终止运行，并在日志文件app.MyLog中记录如下内容：
```
2020-07-05 10:20:41 error 17-3/main.go:10  Eror错误日志
main.main
/Users/monster/GitHub/book-code/Chapter17/17-3/main.go:10
```
提示有一个error，并且指明出错的位置为17 - 3/main.go这个文件的第10行。这在企业级开发中是非常重要的，因为在生产级系统中是不可能调试程序的，我们只能根据日志分析并修正错误。

### 17.4 定义错误码
在企业级开发中大多是前后端分离开发的，因此作为后端的Go语言需要告诉前端具体是什么错误，以便定位问题。

通常来说，一条错误信息需要包含两部分内容：

（1）直接展示给用户的消息提示。

（2）便于开发人员debug的错误信息。错误信息可能包含敏感信息，因此不宜对外展示。

在开发过程中，我们需要判断错误是哪种类型的，以便做相应的逻辑处理，而通过定制的错误码很容易做到这点。错误码需包含一定的信息，通过错误码我们可以快速判断错误级别、错误模块和具体错误信息。

本节介绍如何定义可以满足业务需求的错误码。

打开本节的源代码文件Chapter 17/myerr/code.go，输入如下代码： （此处仅记录文字，未提及的代码部分未录入） 

### 17.4 定义错误码
```go
var (
    // Common errors
    OK                  = &ErrNum{Code: 0, Message: "OK"}
    InternalServerError = &ErrNum{Code: 30001, Message: "内部错误."}
    ErrBind             = &ErrNum{Code: 30002, Message: "请求信息无法转换成结构"}
    ErrDatabase         = &ErrNum{Code: 30002, Message: " 数据库错误."}
    ErrValidation       = &ErrNum{Code: 30101, Message: "校验失败."}
    ErrEncrypt          = &ErrNum{Code: 30101, Message: "密码校验失败."}
    // user errors
    ErrAccountNotFound  = &ErrNum{Code: 50102, Message: "账户不存在."}
    ErrPassword         = &ErrNum{Code: 50103, Message: "密码错误."}
    ErrAccountEmpty     = &ErrNum{Code: 50104, Message: "账户不能为空."}
    ErrPasswordEmpty    = &ErrNum{Code: 50103, Message: "密码不能为空."}
    ErrMissingHeader    = &ErrNum{Code: 50104, Message: " Http Header 不存在"}
    ErrToken            = &ErrNum{Code: 50105, Message: "生成 Token 错误"}
    PassParamCheck      = &ErrNum{Code: 60000, Message: "参数校验通过"}
)
```
在Chapter17/myerr/errnum.go中声明了一个结构体ErrNum，它包含code和message两个属性。Err包含ErrNum和error两个属性。

（1）返回错误消息。
```go
func (e *ErrNum) Error() string
```
（2）返回错误。
```go
func New(num ErrNum, err error) *Err
```
（3）添加错误。
```go
func (e *Err) Add(message string) Err
```
（4）返回错误。
```go
func (err *Err) Error() string
```
```go
type ErrNum struct {
    Code int
    Message string
}

func (e *ErrNum) Error() string {
    return e.Message
}

type Err struct {
    ErrNum ErrNum
    Err error
}

func New(num ErrNum, err error) *Err {
    return &Err{
        ErrNum: ErrNum{Code: num.Code, Message: num.Message},
        Err:    err,
    }
}

func (e *Err) Add(message string) Err {
    e.ErrNum.Message += " " + message
    return *e
}

func (err *Err) AddFormat(format string, args ...interface{}) Err {
    err.ErrNum.Message += " " + fmt.Sprintf(format, args...)
    return *err
}

func (err *Err) Error() string {
    return fmt.Sprintf("Err - code: %d, message: %s, error: %s",
        err.ErrNum.Code,
        err.ErrNum.Message, err.Err)
}

func IsErrAccountNotFound(err error) bool {
    code, _ := DecodeErr(err)
    return code == ErrAccountNotFound.Code
}

func DecodeErr(err error) (int, string) {
    if err == nil {
        return OK.Code, OK.Message
    }
    switch typed := err.(type) {
    case *Err:
        return typed.ErrNum.Code, typed.ErrNum.Message
    case *ErrNum:
        return typed.Code, typed.Message
    default:
        return InternalServerError.Code, err.Error()
    }
}
```
以用户登录为例，请求login登录接口，如果密码匹配失败，则提示密码错误。

```go
if err := utils.Compare(account.Password, m.Password); err != nil {
    res.SendResponse(c, myerr.ErrPassword, nil)
    return
}
```
运行结果如图17 - 1所示。（此处因无法获取图17 - 1实际内容，未对图相关信息记录）

![image](https://github.com/user-attachments/assets/168dbd88-f53b-49d2-b1f9-5f2f059e5eb2)

### 17.5 创建账户
业务逻辑处理是API的核心功能，常见的业务如下：
- 创建账户。
- 删除账户。
- 更新账户。
- 查询账户列表。
- 查询指定账户的信息。
1. **路由配置**
在创建账户之前，需要做路由配置。下面在Chapter 17/router/router.go文件中配置路由信息：

```go
account := engine.Group("/v1/account")
{
    account.POST("", handler.AccountCreate) // 新增用户
    account.GET("", handler.ListAccount) // 获取用户列表
    account.GET("/:account_name", handler.GetAccount) // 获取指定用户的详细信息
    account.DELETE("/:id", handler.Delete) // 删除用户
    account.PUT("/", handler.Update) // 更新用户
    account.POST("/login", handler.Login)
}
```
创建账户的步骤如下：

（1）从HTTP消息体获取参数（用户名和密码）。

（2）参数校验。

（3）加密密码。

（4）在数据库中添加数据记录。

（5）返回结果（这里是用户名）。

打开源码文件Chapter17/handler/account.go，输入如下代码：
```go
//新建一个Account（用户名）
func (h *AccountHandler) AccountCreate(c *gin.Context) {
    var r account.CreateRequest
    if err := c.Bind(&r); err != nil {
        SendResponse(c, myerr.ErrBind, nil)
        return
    }
    if err := utils.CheckParam(r.AccountName,r.Password); err.Err != nil {
        res.SendResponse(c, err.Err, nil)
        return
    }
    accountName := r.AccountName
    MyLog.Log.Infof("用户名: %s", accountName)
    desc := c.Query("desc")
    MyLog.Log.Infof("desc: %s", desc)
    contentType := c.GetHeader("Content-Type")
    MyLog.Log.Infof("Header Content-Type: %s", contentType)
    //把明文密码加密
    md5Pwd,err := utils.Encrypt(r.Password)
    if err != nil {
        res.SendResponse(c, myerr.ErrEncrypt, nil)
        return
    }
    id ,err := uuid.GenerateUUID()
    if err!=nil{
        res.SendResponse(c, myerr.InternalServerError, nil)
        return
    }
    a :=model.Account{
        AccountId: id,
        AccountName: r.AccountName,
        Password:  md5Pwd,
    }
    if err := h.Srv.CreateAccount(a); err != nil {
        res.SendResponse(c, myerr.ErrDatabase, nil)
        return
    }
    rsp := account.CreateResponse{
        AccountName: r.AccountName,
    }
    res.SendResponse(c, nil, rsp)
}
```
打开源代码文件Chapter17/utils/auth.go，输入如下代码：
```go
func CheckParam(accountName,password string) myerr.Err {
    if accountName == "" {
        return myerr.New(myerr.ErrValidation, nil).Add("用户名为空.")
    }
    if password == "" {
        return myerr.New(myerr.ErrValidation, nil).Add("密码为空.")
    }
    return myerr.Err{ErrNum: *myerr.PassParamCheck, Err: nil}
}
// 给文本加密
func Encrypt(source string) (string, error) {
    hashedBytes,  err  :=  bcrypt.GenerateFromPassword([]byte(source), bcrypt.DefaultCost)
    return string(hashedBytes), err
}
```
通常在服务层中组合业务逻辑：
```go
// Chapter17/service/account.go
func (ac *AccountService) CreateAccount(account model.Account) error{
    return ac.Repo.CreateAccount(account)
}
```
打开源代码文件Chapter17/repository/account.go，输入如下代码：
```go
// 在数据库中新建一个Account
func (m *AccountModelRepo) CreateAccount(account model.Account) error {
    return m.DB.MyDB.Create(&account).Error
}
``` 
### 17.5 创建账户
在上述代码中，是通过CreateAccount函数向数据库中添加记录的。

另外，使用postwoman工具可以调试RESTful风格的接口。在添加成功后，会输出新建账户的名称——Tom，如图17 - 2所示。（此处因无法获取图17 - 2实际内容，未对图相关信息记录）

![image](https://github.com/user-attachments/assets/3c71d48b-71a0-4163-82e2-7daf753444c5)

在数据库中，打开Mysql WorkBench，输入下面的SQL语句，显示如图17 - 3所示。（此处因无法获取图17 - 3实际内容，未对图相关信息记录）

![image](https://github.com/user-attachments/assets/e6bf532d-9b8f-4cfe-b595-e079cec62ba0)

```sql
SELECT * FROM db.account;
```
至此，我们就成功把Tom添加到数据库中了，同时可以看到，password中的内容都已加密。

### 17.6 删除账户
在删除账户时，首先根据URL路径DELETE http://127.0.0.1/v1/user/1解析出ID的值为1，该ID实际上就是数据库中的ID索引，然后调用model.DeleteUser函数将其删除，具体代码如下：
```go
// handler/account.go
func (h *AccountHandler) Delete(c *gin.Context) {
    accountId, _ := c.Param("id")
    if err := h.Srv.DeleteAccount(accountId); err != nil {
        res.SendResponse(c, myerr.ErrDatabase, nil)
        return
    }
    SendResponse(c, nil, nil)
}
```
（1）获取要删除的ID。

（2）执行删除方法h.Srv.DeleteAccount()。

打开源代码文件Chapter17/service/account.go，输入如下内容：
```go
func (ac *AccountService) DeleteAccount(id string) error{
    return ac.Repo.DeleteAccount(id)
}
```
打开源代码文件Chapter17/repository/account.go，输入如下内容：
```go
// 通过ID删除Account
func (m *AccountModelRepo) DeleteAccount(id string) error {
    err := m.DB.MyDB.Where("account_id =?", id).Delete(&model.Account{}).Error
    if err != nil {
        return err
    }
    return nil
}
```
这里通过调用Delete方法删除了用户，这种删除是物理删除。还有一种删除叫作软删除，就是在数据库中设置delete_status字段，0表示正常，1表示删除，进而更新delete_status字段得到删除的效果。

### 17.7 更新账户

更新账户的主要步骤如下：

（1）获取要更新的accountId。

（2）绑定account。

（3）验证参数。

（4）更新操作。

打开源代码文件Chapter17/handler/account.go，输入如下内容：
```go
func (h *AccountHandler) Update(c *gin.Context) {
    MyLog.Log.Info("执行更新操作.Request-Id: ",utils.GetRequestID(c))
    //通过参数c.Bind(&m) 绑定account
    var m account.Model
    if err := c.Bind(&m); err != nil {
        SendResponse(c, myerr.ErrBind, nil)
        return
    }
    //对密码进行加密处理
    md5Pwd,err := utils.Encrypt(m.Password)
    if err != nil {
        SendResponse(c, myerr.ErrEncrypt, nil)
        return
    }
    m.Password=md5Pwd
    //保存更新
    if err := h.Srv.UpdateAccount(); err != nil {
        SendResponse(c, myerr.ErrDatabase, nil)
        return
    }
    SendResponse(c, nil, nil)
}
```
在service层中，我们做业务逻辑判断的步骤如下：

（1）搜索要更新的账户，如果不存在，则返回错误信息给前端。

（2）如果搜索的账户ID为空，刚返回错误信息给前端。

根据业务场景，可以继续增加业务逻辑判断。

当业务逻辑判断都成功时，才调用数据访问层的UpdateAccount方法进行更新。如图17 - 4所示。（此处因无法获取图17 - 4实际内容，未对图相关信息记录）

![image](https://github.com/user-attachments/assets/34df1b24-7227-41d4-a02b-8b33b2263ee5)


```go
func (ac *AccountService) UpdateAccount(account model.Account) error {
    accountInfo, err := ac.Repo.GetAccountInfo(account.AccountId)
    if err != nil {
        return err
    }
    if accountInfo.AccountId=="" {
        return errors.New("用户不存在")
    }
    return ac.Repo.UpdateAccount(account)
}
```
```go
func (m *AccountModelRepo) UpdateAccount(account model.Account) error {
    err := m.DB.MyDB.Model(model.Account{}).Where("account_id=?",account.AccountId).Updates(map[string]interface{}{
        "account_name":account.AccountName,
        "account_password":account.Password,
    }).Error
    return err
}
```
更新后的数据库对应记录如图17 - 5所示。（此处因无法获取图17 - 5实际内容，未对图相关信息记录）
从图17 - 5可以看出，账户名已成功由原来的Tom更新为Tom777。

![image](https://github.com/user-attachments/assets/a24c8f35-c8fc-425c-8c81-0a63e7c61c36)

### 17.8 账户列表

本节实现如何从数据库里分页取得账户列表。用户在注册以后，我们会把用户的数据直接记录到数据库中，在需要展示时，再通过页面展示出来。如果账户列表里面有1000条甚至更多的数据，则不会一次性都展示出来，因为一次性展示出来会占用大量的带宽，让前端页面一直等待，用户体验非常差，甚至有页面卡死的情况。分页的好处是，一次只拿固定数量的账户数据，而且速度很快，这样前端页面展示也会很快，用户体验很好。

打开源代码文件Chapter17/handler/account.go，输入如下内容：
```go
func (h *AccountHandler) ListAccount(c *gin.Context) {
    var r account.ListRequest
    if err := c.Bind(&r); err != nil {
        SendResponse(c, myerr.ErrBind, nil)
        return
    }
    if r.Offset < 0 {
        r.Offset = 0
    }
    if r.Limit < 1 {
        r.Limit = utils.Limit
    }
    list, count, err := h.Srv.ListAccount(r.Offset, r.Limit)
    if err != nil {
        SendResponse(c, err, nil)
        return
    }
    resp:=[]*res.AccountResp{}
    for _,item :=range list{
        r:=res.AccountResp{AccountName: item.AccountName}
        resp = append(resp,&r )
    }
    SendResponse(c, nil, account.ListResponse{
        TotalCount:  count,
        AccountList: resp,
    })
}
```
打开源代码文件Chapter17/service/account.go，输入如下内容：
```go
func (ac *AccountService) ListAccount(offset, limit int) ([]*account.Info, uint64, error) {
    infos := make([]*account.Info, 0)
    accounts, count, err := ac.Repo.ListAccount(offset, limit)
    if err != nil {
        return nil, count, err
    }
    for _, item := range accounts {
        info := &account.Info{
            Id:         item.Id,
            AccountName: item.AccountName,
            Password:   item.Password,
            CreatedAt:  item.CreatedAt.String(),
            UpdatedAt:  item.UpdatedAt.String(),
        }
        infos = append(infos, info)
    }
    return infos, count, nil
}
```
```go
// Chapter17/repository/account.go
func (m *AccountModelRepo) ListAccount(offset, limit int) ([]*Model, uint64, error) {
    accounts := make([]*Model, 0)
    var count uint64
    if err := m.DB.MyDB.Model(&Model{}).Count(&count).Error; err != nil {
        return nil, 0, err
    }
    err := m.DB.MyDB.Model(&Model{}).Limit(limit).Offset(offset).Order("id desc").Find(&accounts).Error;
    if err != nil {
        return nil, count, err
    }
    return accounts, count, nil
}
```
账户列表如图17 - 6所示，我们可以根据分页的条件返回数据，同时可以返回数据库内一共有多少条数据。在日常开发中，密码是不返回的，除此之外，对于一些敏感信息也是不返回的，比如身份证号码等。另外，对手机号也进行了一定的处理，比如中间加入*号来隐藏信息。这里暂且只返回账户名称，在生产环境中可以返回更多的信息。（此处因无法获取图17 - 6实际内容，未对图相关信息记录） 

![image](https://github.com/user-attachments/assets/25cdacec-6f64-404e-b658-93a482c181cf)


### 17.9 根据账户名称查询用户信息
打开本节的源码文件Chapter17/handler/account.go，输入如下内容：
```go
func (h *AccountHandler) GetAccount(c *gin.Context) {
    accountName := c.Param("account_name")
    // 从数据库中选择Account
    account, err := h.Srv.GetAccount(accountName)
    if err != nil {
        SendResponse(c, myerr.ErrAccountNotFound, nil)
        return
    }
    r:=res.AccountResp{AccountName: account.AccountName}
    SendResponse(c, nil, r)
}
```
c.Param("account_name")//获取账户名称
打开本节的源码文件Chapter17/service/account.go，输入如下内容：
```go
func (ac *AccountService) GetAccount(accountName string) (model.Account, error) {
    return ac.Repo.GetAccountByName(accountName)
}
```
下面根据传入的账户名称在数据库中查询并获取账户信息。

打开本节的源码文件Chapter17/repository/account.go，输入如下内容：
```go
func (m *AccountModelRepo) GetAccount(name string) (model.Account, error) {
    var account model.Account
    err := m.DB.MyDB.Where("account_name =?", name).First(&account).Error
    if err != nil {
        return account,err
    }
    return account, nil
}
```
至此，我们就通过给定的账户名称找到了一个账户，并返回给前端，如图17 - 7所示。（此处因无法获取图17 - 7实际内容，未对图相关信息记录）
![image](https://github.com/user-attachments/assets/ffec4a59-1859-4d54-8efa-e93943962190)



### 17.10 OAuth 2.0简介

OAuth 2.0是一种授权协议，它可以用来保证第三方（软件）只有在获得授权之后，才可以进一步访问授权者的数据。

OAuth 2.0是如何运转的呢？下面把“小明”“生活点评”“微信开放平台”放到一个场景里，看看它们是如何沟通的。

小明：生活点评，我正在浏览器上，需要访问你来帮我查询我的订餐订单。

生活点评：好的，小明，我必须有你的微信个人信息才能查询你的订餐订单，现在我把你引导到微信开放平台上，需要你给我授权。

微信开放平台：你好，小明，我收到了生活点评跳转过来的请求，现在已经准备好了授权页面。你登录并确认后，单击授权页面上的“授权”按钮就可以了。

小明：好的，微信开放平台，我已看到授权页面，并已单击完授权按钮了。

微信开放平台：你好，生活点评，我已收到小明的授权，现在给你生成一个授权码。我将通过浏览器重定向到你的回调URL地址。

生活点评：好的，微信开放平台，我已从浏览器上拿到了授权码，现在就用这个授权码请求你给我一个访问令牌。

微信开放平台：好的，生活点评，访问令牌已经发送给你了。

生活点评：我已收到令牌，现在可以使用令牌访问小明的订单了。

小明：我已经看到我的订单了。

至此，相信你已完全明白OAuth 2.0是如何运转的了。

### 17.11 OAuth 2.0的四种授权模式

当客户端想要访问某一个资源时，此时有两个角色——客户端和资源所有者。只有在资源所有者同意之后，资源服务器才可以向客户端颁发令牌。客户端在拿到令牌后，每次请求资源时，都要带着这个令牌，以便资源服务器通过验证后，才能放行，继续获取资源。

OAuth 2.0提供了4种授权模式：

- 授权码（authorization_code）；
- 隐藏式（implicit）；
- 密码式（password）；
- 客户端凭证（client_credentials）。
  
无论使用哪一种授权模式，第三方应用在申请令牌之前，都必须到相应的系统进行备案。在本例中需要到微信小程序系统进行备案，以便拿到身份识别码的客户端ID（client id）和客户端密钥（client_secret）。这是区分该应用与其他应用的凭证，如果不做备案，那么是拿不到小程序令牌的。
1. **授权码**
授权码是指第三方应用先申请一个授权码，然后用该授权码获取令牌。这种方式最为常用，安全性也最高，适用于有后端的Web应用。

授权码是通过前端（页面）发送的，而令牌则存储在后端，所有与资源服务器的通信都在后端完成的，这样即可避免令牌泄露。

第1步，A应用向开放平台发出请求：
```
https://开放平台/oauth/authorize?
    response_type=code&
    client_id=CLIENT_ID&
    redirect_uri=CALLBACK_URL&
    scope=read
```
说明：
- 参数response_type为要求返回的授权码；
- 参数client_id可以让B网站知道是谁在请求授权码（这是在之前申请备案后自动分配的）；
- 参数redirect_uri是B网站接受或拒绝请求后的跳转网址（网址是在申请备案后就填写好的）；
- 参数scope为要求的授权范围（这里是只读的）。
第2步，跳转到开放平台后，首先会要求用户登录，然后询问用户是否同意授权A应用。用户单击“同意”按钮后，开放平台会跳转到redirect_uri参数指定的网址，并带有授权码。格式如下：
```
coolpest8.com/callback?code=AUTHORIZATION_CODE
```
其中，CODE就是授权码。
第3步，A应用在拿到授权码之后，就可以在后端向开放平台请求令牌了。
```
https://b.com/oauth/token?client_id=CLIENT_ID&client_secret=CLIENT_SECRET&grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=CALLBACK_URL
```
在上面这个URL中：
- 参数client_id和参数client_secret是用来让开放平台确认A应用身份的；
- 参数client_secret是系统分配的，必须保密，因此只能在后端发起请求；
- 参数grant_type的值是authorization_code，表示采用的授权方式是授权码；
- 参数code是上一步拿到的授权码；
- 参数redirect_uri是令牌颁发后的回调网址。
第4步，开放平台在收到请求后进行验证，若验证通过，就颁发令牌，向redirect_uri指定的网址发送JSON格式的数据，代码如下：
```json
{
    "access_token":"ACCESS_TOKEN",
    "token_type":"bearer",
    "expires_in":2592000,
    "refresh_token":"REFRESH_TOKEN",
    "scope":"read",
    "uid":100101,
    "info":{...}
}
```
其中，access_token是令牌。
2. **隐藏式**
隐藏式适用于只有前端没有后端的场景，把令牌存储在前端，直接向前端颁发令牌。因为没有授权码中间的过程，所以是隐藏式。
第1步，A应用向开放平台发出请求：
```
https://coolpest8.com/oauth/authorize?
    response_type=token&
    client_id=CLIENT_ID&
    redirect_uri=CALLBACK_URL&
    scope=read
```

其中，参数response_type表示要求直接返回令牌。

第2步，用户跳转到开放平台，登录后同意给予A应用授权。

此时开放平台会跳回redirect_uri参数指定的网址，并且把令牌作为URL参数传给A应用。格式如下：
```
https://a.com/callback#token=ACCESS_TOKEN
```
其中，token参数是令牌，因此A应用可直接在前端拿到令牌。

这种方式是把令牌直接传送给前端，因而很不安全。

隐藏式只能用在一些对安全要求不高的场景，并且令牌的有效期必须非常短，通常是仅在会话期间（session）有效，当浏览器关掉后，令牌就失效了。 

3. **密码式** 
A应用要求用户提供他在B网站的用户名和密码，在拿到以后，A应用可直接向B网站请求令牌。 （此处未提及相关代码，无代码记录） 

### 17.11 OAuth 2.0的四种授权模式（续）
3. **密码式** 
第1步，A应用向开放平台发出请求：
```
https://开放平台/token?
    grant_type=password&
    username=USERNAME&
    password=PASSWORD&
    client_id=CLIENT_ID
```
其中，参数grant_type是授权方式，这里的password表示使用的是“密码式”，username和password是B的用户名和密码。

第2步，开放平台在验证身份通过后，直接给出令牌。

注意：这里不需要跳转，而是把令牌放在JSON数据里面作为HTTP返回给A应用，从而A应用拿到令牌。

这种方式需要用户给出自己的用户名和密码，显然风险很大。一般在同一家公司的不同应用之间可以使用密码式。
4. **凭证式** 
第1步，A应用向开放平台发出请求：
```
https://开放平台/token?
    grant_type=client_credentials&
    client_id=CLIENT_ID&
    client_secret=CLIENT_SECRET
```
其中，参数grant_type是client_credentials，表示采用的是“凭证式”；参数client_id和参数client_secret可以让开放平台确认A应用的身份。

第2步，开放平台在验证通过以后，直接返回令牌。

这种方式给出的令牌是针对第三方应用的，而不是针对用户的，即有可能出现多个用户共享同一个令牌的情况。

这种要注意使用场景，防止更新多个令牌的风险。

### 使用令牌
A应用在拿到令牌之后，就可以向B网站的API请求数据了。

每次请求API时，在header中都必须带上令牌，格式如下：
```
curl -H "Authorization: Bearer ACCESS_TOKEN" \
"https://api.开放平台.com/getUserInfo"
```

### 更新令牌
在令牌的有效期到了之后，用户无须重新“走”一遍上面的流程，再申请一个新的令牌，因为OAuth 2.0允许用户自动更新令牌。具体方法是，开放平台在颁发令牌时，一次性颁发两个令牌，一个用于获取数据，另一个用于获取新的令牌（refresh_token）。在令牌到期之前，用户可使用refresh_token发起一个请求去更新令牌。

A应用向开放平台发出请求：
```
https://开放平台/oauth/token?
    grant_type=refresh_token&
    client_id=CLIENT_ID&
    client_secret=CLIENT_SECRET&
    refresh_token=REFRESH_TOKEN
```
说明：
- 参数grant_type为refresh_token时表示要求更新令牌；
- 参数client_id和参数client_secret用来确认身份；
- 参数refresh_token表示使用更新后的令牌。

  
开放平台在验证通过之后，就可以颁发新的令牌给用户了。开放平台总是使用用户的openId来标识一个用户的，我们可以在Account表中保存这个字段，当用户授权且开放平台回调后，我们就可以拿到用户的openId了，具体如图17 - 8所示。（此处因无法获取图17 - 8实际内容，未对图相关信息记录）

![image](https://github.com/user-attachments/assets/7e6de6e6-e594-4f5d-a112-35590cbe2095)


（1）在开放平台注册应用，获取appId和appSecret。

（2）通过wx.login方法拿到code，这个code是在前端返回的。

（3）前端首先通过接口调用后端（开发者服务器，就是我们写的Go程序），然后再调用auth.code2Session接口，获取openId和会话密钥sessionKey。Go程序请求接口如下：
```
https://api.weixin.qq.com/sns/jscode2session?appid=APPID&secret=SECRET&js_code=JSCODE&grant_type=authorization_code
```
说明：
- 参数APPID为小程序appId（申请后得到）。
- 参数SECRET为小程序appSecret（申请后得到）。
- 参数JSCODE为前端页面传入的code。
- 参数grant_type为授权类型，此处填写authorization_code，返回的值是JSON。
- openId：用户唯一标识。
- sessionKey：会话密钥。
- ErrCode：错误码。
- ErrMsg：错误信息。
- -1：系统繁忙。
- 0：请求成功。
- 40029：code无效。
- 45011：频率限制，每个用户每分钟100次。
通过上面的步骤，即可拿到用户微信的唯一ID，即openId。

### Go语言实现相关代码
在router.go里增加如下代码：
```go
account := engine.Group("/v1/account")
{
   ...
    account.POST("/wxlogin", AccountHandler.WXLogin)
}
```
### Handler/account.go
```go
//微信小程序登录
func (h *AccountHandler) WXLogin(c *gin.Context) {
    code := c.Query("code")  //获取code
    //根据code获取openId和sessionKey
    wxLoginResp,err := wx_service.WXLogin(code)
    if err != nil {
        res.SendResponse(c, nil, nil)
        return
    }
    // 保存登录态
    session := sessions.Default(c)
    session.Set("openid", wxLoginResp.OpenId)
    session.Set("sessionKey", wxLoginResp.SessionKey )
    // 既可以用openId和sessionKey的串接，也可以用自定义的规则进行拼接，之后进行MD5校验，将其作为该用户的自定义登录态，要保证mySession唯一
    mySession := utils.GetMD5Encode(wxLoginResp.OpenId + wxLoginResp.SessionKey)
    // 接下来可以将openId、sessionKey和mySession存储到数据库或缓存中，可以用mySession去索引openId和sessionKey
    res.SendResponse(c, nil, mySession)
}
```
### Service/wx_service/WXService.go
```go
// 这个函数是以code作为输入的，可以返回调用微信接口后得到的对象指针或异常情况
func WXLogin(code string) (*res.WXLoginResponse, error) {
    url := "https://api.weixin.qq.com/sns/jscode2session?appid=%s&secret=%s&js_code=%s&grant_type=authorization_code"
    url = fmt.Sprintf(url, viper.GetString("wx_app_id"), viper.GetString("wx_secret"), code)

    //创建GET请求
    resp,err := http.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    //解析HTTP请求中的body数据到我们定义的结构体中
    wxResp := res.WXLoginResponse{}
    decoder := json.NewDecoder(resp.Body)
    if err := decoder.Decode(&wxResp); err != nil {
        return nil, err
    }

    //判断微信接口是否返回一个异常情况
    if wxResp.ErrCode != 0 {
        return nil, errors.New(fmt.Sprintf("ErrCode:%s  ErrMsg:%s", wxResp.ErrCode,wxResp.ErrMsg))
    }
    return &wxResp, nil
}
``` 

