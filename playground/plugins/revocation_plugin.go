package plugins

type entity struct {
	userId string
}

func update(req string, res string) (string, string) {
	return req, res
}

func upsert(req string, res string) (string, string) {
	return req, res
}

func matchOrRaise(prop string, entity entity) bool {
	if prop == "*" {
		return true
	}

	//TODO convert it to golang
	//if self.allows:
	//	if not any(match(v) for v in self.allows):
	//		raise AuthorizationError(f"Not allowed user [{entity.user_id}]")
	//if self.blocks:
	//	if any(match(v) for v in self.blocks):
	//raise AuthorizationError(f"Blocked user [{entity.user_id}]")

	if entity.userId == "" {
		panic("")
	}

	return prop == entity.userId
}
