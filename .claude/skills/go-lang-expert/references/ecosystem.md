# Go Ecosystem

Popular libraries by domain.

## Table of Contents
- [Web Frameworks](#web-frameworks)
- [CLI Tools](#cli-tools)
- [Database](#database)
- [Logging](#logging)
- [Configuration](#configuration)
- [Testing](#testing)
- [Observability](#observability)
- [HTTP Clients](#http-clients)
- [Validation](#validation)
- [Authentication](#authentication)

## Web Frameworks

### Standard Library (net/http)

```go
import "net/http"

http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, World!")
})
http.ListenAndServe(":8080", nil)
```

**Best for:** Simple APIs, learning Go, full control

### Gin

```go
import "github.com/gin-gonic/gin"

r := gin.Default()
r.GET("/ping", func(c *gin.Context) {
    c.JSON(200, gin.H{"message": "pong"})
})
r.Run(":8080")
```

**Best for:** REST APIs, middleware-heavy apps, performance

### Echo

```go
import "github.com/labstack/echo/v4"

e := echo.New()
e.GET("/", func(c echo.Context) error {
    return c.String(http.StatusOK, "Hello!")
})
e.Start(":8080")
```

**Best for:** REST APIs, extensibility, good docs

### Chi

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()
r.Get("/", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Hello!"))
})
http.ListenAndServe(":8080", r)
```

**Best for:** net/http compatible, composable routers, middleware

### Fiber

```go
import "github.com/gofiber/fiber/v2"

app := fiber.New()
app.Get("/", func(c *fiber.Ctx) error {
    return c.SendString("Hello!")
})
app.Listen(":8080")
```

**Best for:** Express.js-like API, high performance, familiar syntax

### Comparison

| Framework | Performance | Learning Curve | net/http Compatible |
|-----------|-------------|----------------|---------------------|
| net/http | Good | Low | Yes |
| Gin | Excellent | Low | No |
| Echo | Excellent | Low | No |
| Chi | Good | Low | Yes |
| Fiber | Excellent | Low | No (fasthttp) |

## CLI Tools

### Cobra

```go
import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
    Use:   "app",
    Short: "My CLI app",
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("Hello!")
    },
}

func main() {
    rootCmd.Execute()
}
```

**Best for:** Complex CLIs with subcommands, most popular

### urfave/cli

```go
import "github.com/urfave/cli/v2"

app := &cli.App{
    Name:  "app",
    Usage: "My CLI app",
    Action: func(c *cli.Context) error {
        fmt.Println("Hello!")
        return nil
    },
}
app.Run(os.Args)
```

**Best for:** Simple to moderate CLIs, clean API

### Kong

```go
import "github.com/alecthomas/kong"

var CLI struct {
    Name string `arg:"" help:"Name to greet."`
}

func main() {
    kong.Parse(&CLI)
    fmt.Printf("Hello, %s!\n", CLI.Name)
}
```

**Best for:** Struct-based configuration, type safety

## TUI (Terminal UI)

### Bubble Tea

```go
import tea "github.com/charmbracelet/bubbletea"

type model struct {
    cursor int
    items  []string
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
    switch msg := msg.(type) {
    case tea.KeyMsg:
        switch msg.String() {
        case "q":
            return m, tea.Quit
        case "up":
            if m.cursor > 0 {
                m.cursor--
            }
        case "down":
            if m.cursor < len(m.items)-1 {
                m.cursor++
            }
        }
    }
    return m, nil
}

func (m model) View() string {
    s := "Select item:\n\n"
    for i, item := range m.items {
        cursor := " "
        if m.cursor == i {
            cursor = ">"
        }
        s += fmt.Sprintf("%s %s\n", cursor, item)
    }
    return s
}

func main() {
    p := tea.NewProgram(model{items: []string{"Item 1", "Item 2"}})
    p.Run()
}
```

**Best for:** Interactive terminal apps, Elm architecture

### Lip Gloss

```go
import "github.com/charmbracelet/lipgloss"

var style = lipgloss.NewStyle().
    Bold(true).
    Foreground(lipgloss.Color("205")).
    Background(lipgloss.Color("236")).
    Padding(1, 2)

fmt.Println(style.Render("Hello, World!"))
```

**Best for:** Terminal styling, colors, layouts

### Bubbles

```go
import "github.com/charmbracelet/bubbles/textinput"

ti := textinput.New()
ti.Placeholder = "Enter name"
ti.Focus()
```

**Best for:** Reusable TUI components (inputs, lists, spinners)

### Comparison

| Library | Purpose |
|---------|---------|
| Bubble Tea | Application framework (Elm architecture) |
| Lip Gloss | Styling and layout |
| Bubbles | Pre-built components |

## Database

### database/sql (Standard)

```go
import "database/sql"
import _ "github.com/lib/pq"  // PostgreSQL driver

db, _ := sql.Open("postgres", connStr)
rows, _ := db.Query("SELECT id, name FROM users")
```

### sqlx

```go
import "github.com/jmoiron/sqlx"

type User struct {
    ID   int    `db:"id"`
    Name string `db:"name"`
}

db := sqlx.MustConnect("postgres", connStr)
var users []User
db.Select(&users, "SELECT * FROM users")
```

**Best for:** Extensions to database/sql, struct scanning

### pgx (PostgreSQL)

```go
import "github.com/jackc/pgx/v5"

conn, _ := pgx.Connect(ctx, connStr)
rows, _ := conn.Query(ctx, "SELECT * FROM users")
```

**Best for:** PostgreSQL-specific features, performance

### GORM

```go
import "gorm.io/gorm"
import "gorm.io/driver/postgres"

type User struct {
    gorm.Model
    Name string
}

db, _ := gorm.Open(postgres.Open(connStr))
db.AutoMigrate(&User{})
db.Create(&User{Name: "John"})
```

**Best for:** Full ORM features, rapid development

### ent

```go
// Schema definition
type User struct {
    ent.Schema
}

func (User) Fields() []ent.Field {
    return []ent.Field{
        field.String("name"),
    }
}

// Usage
client.User.Create().SetName("John").Save(ctx)
```

**Best for:** Type-safe queries, code generation, graph traversal

## Logging

### slog (Standard Library, Go 1.21+)

```go
import "log/slog"

logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
logger.Info("user logged in", "user_id", 123)
```

**Best for:** Standard structured logging, Go 1.21+

### Zap

```go
import "go.uber.org/zap"

logger, _ := zap.NewProduction()
logger.Info("user logged in", zap.Int("user_id", 123))

// Sugar logger for convenience
sugar := logger.Sugar()
sugar.Infow("user logged in", "user_id", 123)
```

**Best for:** High performance, production use

### Zerolog

```go
import "github.com/rs/zerolog/log"

log.Info().Int("user_id", 123).Msg("user logged in")
```

**Best for:** Zero allocation, JSON logging

### Comparison

| Logger | Allocations | API Style | JSON |
|--------|-------------|-----------|------|
| slog | Low | Fluent | Yes |
| Zap | Zero | Builder | Yes |
| Zerolog | Zero | Chain | Yes |

## Configuration

### Viper

```go
import "github.com/spf13/viper"

viper.SetConfigName("config")
viper.AddConfigPath(".")
viper.ReadInConfig()

port := viper.GetInt("server.port")
```

**Best for:** Complex config, multiple sources, Cobra integration

### envconfig

```go
import "github.com/kelseyhightower/envconfig"

type Config struct {
    Port int    `envconfig:"PORT" default:"8080"`
    Host string `envconfig:"HOST" default:"localhost"`
}

var cfg Config
envconfig.Process("APP", &cfg)
```

**Best for:** Environment variables, 12-factor apps

### koanf

```go
import "github.com/knadh/koanf/v2"

k := koanf.New(".")
k.Load(file.Provider("config.yaml"), yaml.Parser())
port := k.Int("server.port")
```

**Best for:** Flexible, multiple formats, hot reload

## Testing

### testify

```go
import "github.com/stretchr/testify/assert"
import "github.com/stretchr/testify/require"

func TestSomething(t *testing.T) {
    assert.Equal(t, 123, result)      // Continues on failure
    require.NoError(t, err)           // Stops on failure
}
```

**Best for:** Assertions, mocking, test suites

### gomock

```go
// go install go.uber.org/mock/mockgen@latest
// mockgen -source=foo.go -destination=mock_foo.go

ctrl := gomock.NewController(t)
mock := NewMockFoo(ctrl)
mock.EXPECT().Bar().Return("baz")
```

**Best for:** Interface mocking, expectations

### mockery

```go
// go install github.com/vektra/mockery/v2@latest
// mockery --name=Foo

mock := mocks.NewFoo(t)
mock.On("Bar").Return("baz")
```

**Best for:** testify-style mocks, easier API

### ginkgo/gomega

```go
import . "github.com/onsi/ginkgo/v2"
import . "github.com/onsi/gomega"

var _ = Describe("Calculator", func() {
    It("adds numbers", func() {
        Expect(Add(1, 2)).To(Equal(3))
    })
})
```

**Best for:** BDD-style tests, parallel execution

## Observability

### Prometheus

```go
import "github.com/prometheus/client_golang/prometheus"

var requests = prometheus.NewCounter(prometheus.CounterOpts{
    Name: "http_requests_total",
})

prometheus.MustRegister(requests)
requests.Inc()
```

**Best for:** Metrics, alerting, Kubernetes

### OpenTelemetry

```go
import "go.opentelemetry.io/otel"

tracer := otel.Tracer("my-app")
ctx, span := tracer.Start(ctx, "operation")
defer span.End()
```

**Best for:** Distributed tracing, vendor-neutral

### DataDog/APM

```go
import "gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"

tracer.Start(tracer.WithService("my-service"))
defer tracer.Stop()
```

**Best for:** Full APM solution, dashboards

## HTTP Clients

### net/http (Standard)

```go
resp, err := http.Get("https://api.example.com")
defer resp.Body.Close()
```

### resty

```go
import "github.com/go-resty/resty/v2"

client := resty.New()
resp, _ := client.R().
    SetHeader("Authorization", "Bearer token").
    SetResult(&User{}).
    Get("https://api.example.com/user")
```

**Best for:** Fluent API, retry, middleware

### req

```go
import "github.com/imroc/req/v3"

client := req.C()
var user User
client.Get("https://api.example.com/user").
    SetBearerAuthToken("token").
    Do().Into(&user)
```

**Best for:** Modern API, auto retry, debugging

## Validation

### validator

```go
import "github.com/go-playground/validator/v10"

type User struct {
    Email string `validate:"required,email"`
    Age   int    `validate:"gte=0,lte=130"`
}

validate := validator.New()
err := validate.Struct(user)
```

**Best for:** Struct validation, custom validators

### ozzo-validation

```go
import "github.com/go-ozzo/ozzo-validation/v4"

err := validation.ValidateStruct(&user,
    validation.Field(&user.Email, validation.Required, is.Email),
    validation.Field(&user.Age, validation.Min(0), validation.Max(130)),
)
```

**Best for:** Programmatic validation, no struct tags

## Authentication

### jwt-go

```go
import "github.com/golang-jwt/jwt/v5"

token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
    "user_id": 123,
    "exp":     time.Now().Add(time.Hour).Unix(),
})
tokenString, _ := token.SignedString([]byte("secret"))
```

**Best for:** JWT creation and validation

### casbin

```go
import "github.com/casbin/casbin/v2"

e, _ := casbin.NewEnforcer("model.conf", "policy.csv")
allowed, _ := e.Enforce("alice", "data1", "read")
```

**Best for:** Authorization, RBAC, ABAC

### oauth2

```go
import "golang.org/x/oauth2"

conf := &oauth2.Config{
    ClientID:     "client-id",
    ClientSecret: "client-secret",
    Scopes:       []string{"openid", "profile"},
    Endpoint:     google.Endpoint,
}
token, _ := conf.Exchange(ctx, code)
```

**Best for:** OAuth2 flows, provider integration
