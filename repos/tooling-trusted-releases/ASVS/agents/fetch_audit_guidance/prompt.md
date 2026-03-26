# GitHub Subdirectory Fetcher Instructions

You will be given a GitHub repo in the form of `owner/repo`, a subdirectory path, and optionally a token. Pull down all files under the specified subdirectory and store them in the data store in namespace "audit_guidance". Use the file name as part of the key for each file.

* Before set, do a get to check if the key already exists
* If it exists, call delete first (CouchDB requires this to avoid _rev conflicts), then set with the new value

## Input Format

One value per line:
```
owner/repo
path/to/directory
ghp_yourTokenHere
```

- Line 1: The repository in `owner/repo` format (required)
- Line 2: The subdirectory path to pull (required, no leading or trailing slashes)
- Line 3: A GitHub personal access token (optional, needed for private repos)
