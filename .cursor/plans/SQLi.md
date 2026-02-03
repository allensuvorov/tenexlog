# SQL Injection Detection - TDD Approach

## Phase 1: Test Fixture
Create `examples/sqli.log` with samples for all 17 categories.

Format (TSV, matching existing logs):
```
2025-08-28T10:00:00Z	{IP}	example.com	GET	{PATH_WITH_SQLI}	200	1	UA
```

Each category gets unique attacker IP (6.6.6.1 through 6.6.6.17) for easy verification.

### Categories and Sample Payloads

| ID | Category | IP | Sample Path |
|----|----------|-----|-------------|
| 01 | auth_bypass | 6.6.6.1 | `/login?user=admin'--` |
| 02 | union_extract | 6.6.6.2 | `/products?id=1 UNION SELECT password FROM users--` |
| 03 | error_based | 6.6.6.3 | `/page?id=1 AND 1=CONVERT(int,@@version)--` |
| 04 | blind_boolean | 6.6.6.4 | `/page?id=1 AND 1=1--` |
| 05 | blind_time | 6.6.6.5 | `/page?id=1; WAITFOR DELAY '0:0:5'--` |
| 06 | stacked | 6.6.6.6 | `/page?id=1; DROP TABLE users--` |
| 07 | destruction | 6.6.6.7 | `/page?id=1; DELETE FROM users WHERE 1=1--` |
| 08 | manipulation | 6.6.6.8 | `/page?id=1; INSERT INTO users VALUES('x','y')--` |
| 09 | stored_proc | 6.6.6.9 | `/page?id=1; EXEC xp_cmdshell('dir')--` |
| 10 | oob_exfil | 6.6.6.10 | `/page?id=1; SELECT LOAD_FILE('/etc/passwd')--` |
| 11 | comment_obfusc | 6.6.6.11 | `/products?id=1 UN/**/ION SEL/**/ECT * FROM users--` |
| 12 | encoding | 6.6.6.12 | `/login?user=%27%20OR%201%3D1--` |
| 13 | case_manip | 6.6.6.13 | `/products?id=1 uNiOn SeLeCt password FROM users--` |
| 14 | whitespace | 6.6.6.14 | `/login?user='OR(1=1)--` |
| 15 | concat | 6.6.6.15 | `/page?id=1 UNION SELECT CONCAT(user,pass) FROM users--` |
| 16 | second_order | 6.6.6.16 | `/register?name=admin'--` |
| 17 | nosql | 6.6.6.17 | `/api/users?filter={"$gt":""}` |

## Phase 2: Stub + Failing Tests
Create `internal/analyze/sqli.go` with stub:

```go
type AnomalySQLi struct {
    Kind       string    `json:"kind"`
    Category   string    `json:"category"`  // e.g., "union_extract"
    SrcIP      string    `json:"srcIp"`
    FirstSeen  time.Time `json:"firstSeen"`
    LastSeen   time.Time `json:"lastSeen"`
    Hits       int       `json:"hits"`
    Confidence float64   `json:"confidence"`
    Reason     string    `json:"reason"`
    Sample     string    `json:"sample"`    // Example malicious path
}

func DetectSQLi(rows []parse.Event, minHits int) []AnomalySQLi {
    return nil // Stub - tests will fail
}
```

Create `internal/analyze/sqli_test.go`:
- Table-driven tests, one case per category
- Each test expects detector to find anomaly from that category's IP
- All 17 tests fail initially (stub returns nil)

## Phase 3: Incremental Implementation
Implement detection in `sqli.go`, category by category:

### Detection Logic Structure
```go
var SQLiPatterns = []struct {
    Category string
    Patterns []string  // regex patterns
}{
    {"auth_bypass", []string{`'\s*OR\s+.*=`, `'\s*--`, `'\s*#`}},
    {"union_extract", []string{`UNION\s+(ALL\s+)?SELECT`}},
    // ... etc
}
```

### Implementation Order (by impact + simplicity)
1. `union_extract` - high severity, clear pattern
2. `auth_bypass` - high severity, common
3. `destruction` - critical, clear keywords (DROP, DELETE, TRUNCATE)
4. `stacked` - critical, semicolon + keyword
5. `manipulation` - high, INSERT/UPDATE keywords
6. `comment_obfusc` - medium, `/**/` pattern
7. `encoding` - medium, URL decode first
8. `case_manip` - low, case-insensitive matching handles this
9. Remaining categories as time permits

### Core Detection Flow
1. URL-decode path (handle double-encoding)
2. Lowercase for matching
3. Remove `/**/` comments for obfuscation handling
4. Match against patterns
5. Aggregate by IP, calculate confidence

## Phase 4: Wire to API
Modify `cmd/api/handlers.go`:
- Call `analyze.DetectSQLi(rows, 2)`
- Add to response alongside existing anomalies

## File Summary

| File | Action |
|------|--------|
| `examples/sqli.log` | Create - test fixture |
| `internal/analyze/sqli.go` | Create - detector |
| `internal/analyze/sqli_test.go` | Create - tests |
| `cmd/api/handlers.go` | Modify - wire detector |
