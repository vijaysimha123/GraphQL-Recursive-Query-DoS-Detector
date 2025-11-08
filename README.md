# GraphQL Recursive Query DoS Detector

A Burp Suite extension that automatically detects recursive/circular GraphQL queries that can lead to Denial of Service (DoS) attacks.

[![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Extension-orange)](https://portswigger.net/burp)
[![Python](https://img.shields.io/badge/Python-2.7%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🎯 Overview

GraphQL's flexible query structure allows clients to request nested data. However, without proper depth limiting, attackers can craft recursive queries where the same field appears within its own nested path, causing infinite resolution loops and server resource exhaustion.

This extension automatically detects such vulnerabilities by analyzing all GraphQL requests passing through Burp Suite.

## ⚡ Features

- **🔍 Automatic Detection**: Scans all HTTP traffic for GraphQL recursive queries
- **📊 Multiple Scan Modes**: HTTP Listener, Passive Scanner, and Manual Context Menu
- **🎯 Accurate Detection**: Identifies true recursion patterns (same field in nested paths)
- **🚫 Duplicate Prevention**: Avoids creating multiple issues for the same request
- **📝 Detailed Reporting**: Shows recursion depth and affected fields
- **🔧 Easy to Use**: Simple right-click context menu for manual analysis
- **💡 Clear Results Tab**: Dedicated UI tab with clear output functionality
- **⚙️ Scope Independent**: Scans all traffic regardless of Burp scope settings

## 🛠️ Installation

### Prerequisites
- Burp Suite (Professional or Community Edition)
- Jython Standalone JAR (for Python extensions)

### Steps

1. **Download Jython**
   ```bash
   wget https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.3/jython-standalone-2.7.3.jar
   ```

2. **Configure Burp Suite**
   - Open Burp Suite
   - Go to `Extender` → `Options`
   - Under "Python Environment", set the location of Jython standalone JAR
   - Click "Select file" and choose the downloaded JAR

3. **Load the Extension**
   - Go to `Extender` → `Extensions`
   - Click `Add`
   - Set Extension Type to `Python`
   - Select the `graphql_recursive_detector.py` file
   - Click `Next`

4. **Verify Installation**
   - Check the `Output` tab for success messages
   - Look for the `GraphQL Recursion` tab in Burp Suite
   - Verify console shows: "GraphQL Recursive Query Detector loaded successfully!"

## 📖 Usage

### Automatic Scanning

The extension automatically monitors all HTTP traffic:

```
1. Browse your target application normally
2. Send GraphQL requests through Burp Proxy
3. Check the "GraphQL Recursion" tab for detected issues
4. View issues in Target → Issue activity
```

### Manual Scanning

Right-click on any request in Burp:

```
1. Right-click on a request in HTTP History, Proxy, or Repeater
2. Select "Check GraphQL Recursion"
3. View results in the "GraphQL Recursion" tab
4. Issues automatically added to Target → Issue activity
```

### Clear Output

Click the **"Clear Output"** button in the GraphQL Recursion tab to reset the results display.

## 🔬 Detection Examples

### ✅ Vulnerable Query (Detected)

```graphql
{
  user {
    id
    name
    friends {
      id
      name
      friends {
        id
        name
        friends {
          id
          name
        }
      }
    }
  }
}
```

**Detection**: `friends` field appears 3 times in nested path → **VULNERABLE**

### ✅ Multiple Recursive Fields (Detected)

```graphql
{
  post {
    id
    title
    author {
      id
      name
      post {
        id
        title
        author {
          id
          name
        }
      }
    }
  }
}
```

**Detection**: Both `post` and `author` appear recursively → **VULNERABLE**

### ❌ Safe Query (Not Detected)

```graphql
{
  user {
    id
    name
    posts {
      id
      title
      comments {
        text
        author {
          name
        }
      }
    }
  }
}
```

**Detection**: Different fields at each level → **SAFE**

## 📊 Issue Reporting

When a vulnerability is detected, the extension creates a Burp issue with:

- **Severity**: Medium
- **Confidence**: Certain
- **Details**: Recursion depth and affected fields
- **Remediation**: Implementation recommendations

### Issue Details Include:

```
- Recursive Fields: [field1, field2, ...]
- Recursion Depth: N levels
- Attack Vector: Circular field references causing exponential resource consumption
- Remediation: Depth limiting and query complexity analysis recommendations
```

## 🧪 Testing

### Test Cases Included

The extension has been tested with 20+ different GraphQL query patterns including:

- ✅ Simple recursion (user → user → user)
- ✅ Complex social graphs (friends, posts, comments)
- ✅ Organization hierarchies (parent → parent → parent)
- ✅ Mutations with recursion
- ✅ Batched queries
- ✅ Fragments with recursion
- ✅ Subscriptions
- ❌ Normal nested queries (should not detect)
- ❌ Aliased queries (should not detect)
- ❌ Different fields at same level (should not detect)

### Sample Test Request

```http
POST /graphql HTTP/1.1
Host: api.example.com
Content-Type: application/json

{
  "query": "{ user { id name user { id name user { id name } } } }"
}
```

**Expected Result**: Detects recursion with depth 3, field: "user"

## 🔧 Configuration

No additional configuration required. The extension works out of the box with default settings:

- **Scope**: Scans all traffic (scope-independent)
- **Recursion Threshold**: 2+ occurrences of same field in path
- **Detection Method**: Path-based field tracking
- **Issue Severity**: Medium

## 🚀 How It Works

### Detection Algorithm

1. **Request Identification**: Identifies GraphQL requests by URL path and content type
2. **Query Extraction**: Parses JSON body to extract GraphQL query
3. **Token Parsing**: Breaks query into field names and structural tokens
4. **Path Tracking**: Maintains stack of current field path during traversal
5. **Recursion Detection**: Checks if any field appears multiple times in its own path
6. **Issue Creation**: Creates Burp issue when recursion depth ≥ 2

### Technical Details

```python
# Simplified detection logic
currentPath = []
for each field in query:
    if field already in currentPath:
        # Recursion detected!
        depth = currentPath.count(field) + 1
        mark_as_vulnerable(field, depth)
    currentPath.append(field)
```

## 📋 Requirements

- **Burp Suite**: Professional or Community Edition
- **Jython**: 2.7.x
- **Python Libraries**: Standard library only (no external dependencies)

## 🐛 Troubleshooting

### Extension Not Loading

```
Issue: Extension fails to load
Solution: 
1. Verify Jython standalone JAR is configured correctly
2. Check Burp Suite Output tab for error messages
3. Ensure Python file has correct syntax
```

### Not Detecting Queries

```
Issue: GraphQL queries not being detected
Solution:
1. Verify request contains "query", "mutation", or "subscription" keywords
2. Check URL path contains "/graphql", "/graph", or "/gql"
3. Ensure Content-Type is application/json
4. Review console output for detection logs
```

### Duplicate Issues

```
Issue: Multiple issues created for same request
Solution:
The extension automatically prevents duplicates using request hashing.
If you see duplicates, try clearing the extension output and reloading.
```

### False Positives

```
Issue: Normal queries flagged as recursive
Solution:
The extension uses strict path-based detection. If false positives occur,
please report with the query for investigation.
```

## 📝 Console Output

The extension provides detailed console logging:

```
[INIT] Scanner check registered
[INIT] Context menu registered
[INIT] HTTP Listener registered - scanning ALL traffic
[HTTP LISTENER] Found GraphQL request: https://api.example.com/graphql
[HTTP LISTENER] Recursive query detected! Depth: 3
[!] Added vulnerability issue for: https://api.example.com/graphql
[MANUAL SCAN] Added issue to Burp for: https://api.example.com/graphql
[MANUAL SCAN] Skipping duplicate issue for: https://api.example.com/graphql
```

## 🔒 Security Impact

### Attack Scenario

```graphql
# Malicious recursive query
{
  user(id: "1") {
    friends { friends { friends { friends { friends {
      friends { friends { friends { friends { friends {
        id name email
      }}}}}}}}}}
  }
}
```

**Impact**: 
- Server attempts to resolve friends recursively
- Each level multiplies the number of database queries
- Can cause memory exhaustion, CPU spikes, and service unavailability
- Potential for complete DoS with minimal attacker effort

### Recommended Fixes

1. **Implement Query Depth Limiting**
   ```javascript
   // Apollo Server example
   const server = new ApolloServer({
     validationRules: [depthLimit(5)]
   });
   ```

2. **Add Query Complexity Analysis**
   ```javascript
   const complexity = require('graphql-query-complexity');
   const maxComplexity = 1000;
   ```

3. **Use Persistent Queries** (Production)
   - Whitelist allowed queries
   - Reject arbitrary query submissions

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

### Development Setup

```bash
git clone https://github.com/yourusername/graphql-recursive-detector.git
cd graphql-recursive-detector
# Make changes to graphql_recursive_detector.py
# Test in Burp Suite
```

### Reporting Issues

Please include:
- Burp Suite version
- Jython version
- Sample GraphQL query (if applicable)
- Console output
- Steps to reproduce

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Vijaysimha Reddy**


## 📚 References

- [GraphQL Security Best Practices](https://graphql.org/learn/best-practices/)
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html)
- [Burp Suite Extender API](https://portswigger.net/burp/extender/api/)


## 🔄 Changelog

### Version 1.0.0 (2024)
- Initial release
- Automatic HTTP listener scanning
- Passive scanning support
- Manual context menu scanning
- Duplicate detection prevention
- Clear output functionality
- Detailed issue reporting

## ⭐ Star History

If you find this tool useful, please consider giving it a star on GitHub!

---

**Note**: This tool is for authorized security testing only. Always obtain proper permission before testing systems you don't own.
