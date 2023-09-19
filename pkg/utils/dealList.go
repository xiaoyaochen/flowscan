package utils

func Listcontains(slice []string, element string) bool {
	for _, item := range slice {
		if item == element {
			return true
		}
	}
	return false
}

func ListRemoveDuplicates(list []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range list {
		if _, ok := seen[item]; !ok {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
