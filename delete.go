package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type DeleteRequest struct {
	YAML  string `json:"yaml"`
	Index *int   `json:"index"`
}

type DeleteResult struct {
	YAML            string `json:"yaml"`
	DeletedName     string `json:"deletedName"`
	Total           int    `json:"total"`
	RemovedRules    int    `json:"removedRules"`
	SubscriptionURL string `json:"subscriptionURL,omitempty"`
}

func deleteYAML(input string, index *int) (DeleteResult, error) {
	result := DeleteResult{}
	doc, root, err := parseTemplate(input)
	if err != nil {
		return result, err
	}
	proxies := field(root, "proxies")
	if index == nil || *index < 0 || *index >= len(proxies.Content) {
		return result, errors.New("请选择有效的节点进行删除")
	}
	result.DeletedName = nodeText(field(proxies.Content[*index], "name"))
	proxies.Content = append(proxies.Content[:*index], proxies.Content[*index+1:]...)
	// A dependent node or provider must keep its explicit outbound route.
	if dependency := deletionDependency(root, result.DeletedName, map[*yaml.Node]bool{}); dependency != "" {
		return DeleteResult{}, fmt.Errorf("无法删除 %s：仍被 %s 引用，请先修改或删除依赖项", result.DeletedName, dependency)
	}
	for _, group := range nodesOf(field(root, "proxy-groups")) {
		list := field(group, "proxies")
		if list == nil {
			continue
		}
		kept := list.Content[:0]
		for _, entry := range list.Content {
			if entry.Value != result.DeletedName {
				kept = append(kept, entry)
			}
		}
		list.Content = kept
	}
	result.RemovedRules = removeNodeRules(field(root, "rules"), result.DeletedName)
	if subrules := field(root, "sub-rules"); subrules != nil && subrules.Kind == yaml.MappingNode {
		for i := 1; i < len(subrules.Content); i += 2 {
			result.RemovedRules += removeNodeRules(subrules.Content[i], result.DeletedName)
		}
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return DeleteResult{}, errors.New("生成 YAML 失败")
	}
	_ = encoder.Close()
	result.YAML, result.Total = buffer.String(), len(proxies.Content)
	if _, _, err := parseTemplate(result.YAML); err != nil {
		return DeleteResult{}, errors.New("删除后配置存在无效引用（可能包含 YAML 锚点），请先展开别名后重试")
	}
	return result, nil
}

func deletionDependency(node *yaml.Node, name string, visited map[*yaml.Node]bool) string {
	if node == nil || visited[node] {
		return ""
	}
	visited[node] = true
	if node.Kind == yaml.AliasNode {
		return deletionDependency(node.Alias, name, visited)
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i].Value, node.Content[i+1]
			if (key == "proxy" || key == "dialer-proxy") && value.Kind == yaml.ScalarNode && value.Value == name {
				owner := nodeText(field(node, "name"))
				if owner != "" {
					return owner + " 的 " + key
				}
				return key
			}
		}
	}
	for _, child := range node.Content {
		if dependency := deletionDependency(child, name, visited); dependency != "" {
			return dependency
		}
	}
	return ""
}

func removeNodeRules(list *yaml.Node, name string) int {
	if list == nil || list.Kind != yaml.SequenceNode {
		return 0
	}
	removed := 0
	kept := list.Content[:0]
	for _, entry := range list.Content {
		if entry.Kind == yaml.ScalarNode && !strings.HasPrefix(entry.Value, "SUB-RULE,") {
			target := ruleTarget.FindStringSubmatch(entry.Value)
			if len(target) > 1 && target[1] == name {
				removed++
				continue
			}
		}
		kept = append(kept, entry)
	}
	list.Content = kept
	return removed
}
