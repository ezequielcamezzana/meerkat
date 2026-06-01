package walker

type ecosystemInfo struct {
	Ecosystem      string
	PackageManager string
}

var lockFiles = map[string]ecosystemInfo{
	"package-lock.json": {Ecosystem: "npm", PackageManager: "npm"},
	"yarn.lock":         {Ecosystem: "npm", PackageManager: "yarn"},
	"pnpm-lock.yaml":    {Ecosystem: "npm", PackageManager: "pnpm"},
	"Cargo.lock":        {Ecosystem: "cargo", PackageManager: "cargo"},
	"go.sum":            {Ecosystem: "golang", PackageManager: "gomodules"},
	"poetry.lock":       {Ecosystem: "pypi", PackageManager: "poetry"},
	"Pipfile.lock":      {Ecosystem: "pypi", PackageManager: "pipenv"},
	"uv.lock":           {Ecosystem: "pypi", PackageManager: "uv"},
	"conan.lock":        {Ecosystem: "conan", PackageManager: "conan"},
	"conanfile.txt":     {Ecosystem: "conan", PackageManager: "conan"},
	"conanfile.py":      {Ecosystem: "conan", PackageManager: "conan"},
}

func LockFileInfo(filename string) (ecosystemInfo, bool) {
	info, ok := lockFiles[filename]
	return info, ok
}
