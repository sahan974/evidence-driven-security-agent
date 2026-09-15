// This helper runs inside the replay container and writes only to its temporary filesystem.
package main

import (
    "encoding/json"
    "fmt"
    "go/ast"
    "go/parser"
    "go/token"
    "io/fs"
    "os"
    "os/exec"
    "path/filepath"
    "strconv"
    "strings"
)

func main() {
    if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}

func run() error {
    var command []string
    if err := json.Unmarshal([]byte(os.Args[1]), &command); err != nil { return err }
    if len(command) < 4 || command[0] != "go" || command[1] != "test" {
        return fmt.Errorf("unsupported Go replay command")
    }
    pkg := command[2]
    if pkg != "./..." && pkg != "." && (!strings.HasPrefix(pkg, "./") || strings.Contains(pkg, "..")) {
        return fmt.Errorf("replay must select one local package")
    }
    selector := ""
    for _, arg := range command[3:] {
        if strings.HasPrefix(arg, "-run=^") && strings.HasSuffix(arg, "$") {
            selector = strings.TrimSuffix(strings.TrimPrefix(arg, "-run=^"), "$")
        }
    }
    if !token.IsIdentifier(selector) { return fmt.Errorf("unsupported test selector") }
    var sources map[string]string
    if err := json.Unmarshal([]byte(os.Args[3]), &sources); err != nil { return err }
    packageName, callable, payload := "", "", ""
    matches := 0
    for name, source := range sources {
        file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
        if err != nil { return err }
            for _, declaration := range file.Decls {
                function, ok := declaration.(*ast.FuncDecl)
                if !ok || function.Name.Name != selector { continue }
                matches++
                packageName = file.Name.Name
                directory := filepath.ToSlash(filepath.Dir(name))
                if directory == "." { pkg = "." } else { pkg = "./" + directory }
                // Admit the existing adapter contract: path literal followed by f(path).
                ast.Inspect(function.Body, func(node ast.Node) bool {
                    assignment, ok := node.(*ast.AssignStmt)
                    if !ok || len(assignment.Rhs) != 1 { return true }
                    if len(assignment.Lhs) == 1 {
                        name, named := assignment.Lhs[0].(*ast.Ident)
                        literal, constant := assignment.Rhs[0].(*ast.BasicLit)
                        if named && name.Name == "path" && constant && literal.Kind == token.STRING && assignment.Tok == token.DEFINE {
                            payload, _ = strconv.Unquote(literal.Value)
                        }
                    }
                    call, called := assignment.Rhs[0].(*ast.CallExpr)
                    if !called || len(assignment.Lhs) != 2 || len(call.Args) != 1 { return true }
                    name, named := call.Fun.(*ast.Ident)
                    argument, variable := call.Args[0].(*ast.Ident)
                    if named && variable && argument.Name == "path" {
                        if callable != "" { callable = "ambiguous target!" } else { callable = name.Name }
                    }
                    return true
                })
            }
    }
    if matches != 1 || !token.IsIdentifier(callable) || payload == "" {
        return fmt.Errorf("unsupported Go filesystem replay target")
    }
    temporary, err := os.MkdirTemp("", "edsa-go-patch-")
    if err != nil { return err }
    defer os.RemoveAll(temporary)
    root := filepath.Join(temporary, "application")
    err = filepath.WalkDir(".", func(path string, entry fs.DirEntry, walkErr error) error {
        if walkErr != nil { return walkErr }
        if entry.IsDir() && entry.Name() == ".git" { return filepath.SkipDir }
        destination := filepath.Join(root, path)
        if entry.IsDir() { return os.MkdirAll(destination, 0700) }
        if entry.Type() & os.ModeSymlink != 0 { return fmt.Errorf("source symlink requires explicit support: %s", path) }
        data, readErr := os.ReadFile(path)
        if readErr != nil { return readErr }
        return os.WriteFile(destination, data, 0600)
    })
    if err != nil { return err }
    test := strings.NewReplacer("PACKAGE", packageName, "CALLABLE", callable, "PAYLOAD", strconv.Quote(payload)).Replace(testSource)
    testPath := filepath.Join(root, pkg, "edsa_patch_verification_test.go")
    if _, err := os.Lstat(testPath); !os.IsNotExist(err) { return fmt.Errorf("reserved test path exists") }
    if err := os.WriteFile(testPath, []byte(test), 0600); err != nil { return err }
    process := exec.Command("go", "test", pkg, "-run=^TestEdsaPatchVerification$", "-count=1", "-v")
    process.Dir = root
    process.Env = append(os.Environ(), "EDSA_PATCH_MODE="+os.Args[2])
    process.Stdout, process.Stderr = os.Stdout, os.Stderr
    return process.Run()
}

const testSource = `package PACKAGE
import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
    "testing"
)
func TestEdsaPatchVerification(t *testing.T) {
    root, err := os.Getwd(); if err != nil { t.Fatal(err) }
    sibling, err := os.MkdirTemp(filepath.Dir(root), filepath.Base(root)+"-sibling-")
    if err != nil { t.Fatal(err) }; defer os.RemoveAll(sibling)
    random := make([]byte, 32); if _, err := rand.Read(random); err != nil { t.Fatal(err) }
    marker := hex.EncodeToString(random)
    outside := filepath.Join(sibling, "outside.txt")
    if err := os.WriteFile(outside, []byte(marker), 0600); err != nil { t.Fatal(err) }
    safe := "edsa-safe-"+marker+".txt"
    if err := os.WriteFile(safe, []byte(marker), 0600); err != nil { t.Fatal(err) }
    content, err := CALLABLE(safe)
    if err != nil || string(content) != marker { t.Fatalf("safe read changed: %v", err) }
    inside := "edsa-inside-"+marker
    if err := os.Mkdir(inside, 0700); err != nil { t.Fatal(err) }
    link := "edsa-link-"+marker; directory := "edsa-directory-"+marker
    if err := os.Symlink(outside, link); err != nil { t.Fatal(err) }
    if err := os.Symlink(sibling, directory); err != nil { t.Fatal(err) }
    relative := "../"+filepath.Base(sibling)+"/outside.txt"
    candidates := []string{relative, outside, "./"+relative, inside+"/../"+relative,
        "../"+filepath.Base(sibling)+"/./outside.txt", "../"+filepath.Base(sibling)+"//outside.txt", link, directory+"/outside.txt"}
    mode := os.Getenv("EDSA_PATCH_MODE")
    candidate := PAYLOAD
    if mode != "proof" {
        index, err := strconv.Atoi(mode); if err != nil || index < 0 || index >= len(candidates) { t.Fatal("invalid variant") }
        candidate = candidates[index]
        resolved, err := filepath.EvalSymlinks(candidate); if err != nil { t.Fatal(err) }
        resolved, err = filepath.Abs(resolved); if err != nil || resolved != outside { t.Fatal("invalid outside fixture") }
    }
    _, err = CALLABLE(candidate)
    if err == nil { t.Fatal("candidate returned without rejecting") }
    var pathError *os.PathError
    if errors.As(err, &pathError) { t.Fatalf("filesystem failure does not establish rejection: %v", err) }
    fmt.Printf("candidate=%q rejection=%v\n", candidate, err)
    if mode == "proof" { fmt.Println("EDSA_PATCH_BLOCKED") } else { fmt.Println("EDSA_VARIANT_BLOCKED") }
}
`
