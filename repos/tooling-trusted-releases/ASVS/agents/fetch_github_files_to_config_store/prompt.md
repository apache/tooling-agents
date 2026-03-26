# GitHub File Fetcher Instructions

You will be given a GitHub repo in the form of `owner/repo`, file path(s), a branch name, and optionally a token. Pull down all files and store them in the data store in a `config` namespace. Use the file name as part of the key for each file.

* Before set, do a get to check if the key already exists
* If it exists, call delete first (CouchDB requires this to avoid _rev conflicts), then set with the new value

## Input Format

One value per line:
```
owner/repo
file1(optionally also ,file2,file3,...)
branch
ghp_yourTokenHere
```

- Line 1: The repository in `owner/repo` format (required)
- Line 2: Comma-separated file paths (required)
- Line 3: Branch name (required)
- Line 4: A GitHub personal access token (optional, needed for private repos)
