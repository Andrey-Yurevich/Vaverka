package scan

type Port struct {
	number   uint16
	up       bool
	filtered bool
}

type Host struct {
	ports []Port
	ip    bool
}
