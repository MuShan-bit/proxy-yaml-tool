package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type ConvertOptions struct {
	CleanExisting bool `json:"cleanExisting"`
	SyncGroups    bool `json:"syncGroups"`
	Country       bool `json:"country"`
	MarkExisting  bool `json:"markExisting"`
}
type ConvertRequest struct {
	Template  string         `json:"template"`
	Links     string         `json:"links"`
	NodesYAML string         `json:"nodesYaml"`
	Nodes     []Proxy        `json:"nodes"`
	Servers   string         `json:"servers"`
	Options   ConvertOptions `json:"options"`
}
type RenameRequest struct {
	YAML  string   `json:"yaml"`
	Names []string `json:"names"`
}
type NodeSummary struct {
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Server    string `json:"server"`
	Port      int    `json:"port"`
	Transport string `json:"transport"`
}
type ConvertResult struct {
	YAML            string        `json:"yaml"`
	Added           int           `json:"added"`
	Skipped         int           `json:"skipped"`
	Unsupported     int           `json:"unsupported"`
	Removed         int           `json:"removed"`
	Labeled         int           `json:"labeled"`
	Total           int           `json:"total"`
	Groups          int           `json:"groups"`
	Nodes           []NodeSummary `json:"nodes"`
	Warnings        []string      `json:"warnings"`
	SubscriptionURL string        `json:"subscriptionURL,omitempty"`
}

const blankTemplate = `mixed-port: 7890
allow-lan: false
mode: rule
log-level: info
proxies: []
proxy-groups:
  - name: 自建代理
    type: select
    proxies: [自动选择, 故障转移, DIRECT]
  - name: 自动选择
    type: url-test
    proxies: []
    url: https://www.gstatic.com/generate_204
    interval: 300
  - name: 故障转移
    type: fallback
    proxies: []
    url: https://www.gstatic.com/generate_204
    interval: 300
rules:
  - MATCH,自建代理
`

func field(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}
func setField(node *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			node.Content[i+1] = value
			return
		}
	}
	node.Content = append(node.Content, scalar(key), value)
}
func scalar(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }
func nodeText(node *yaml.Node) string {
	if node == nil {
		return ""
	}
	return node.Value
}

func proxyFromNode(node *yaml.Node) (Proxy, error) {
	var p Proxy
	if node.Kind != yaml.MappingNode || node.Decode(&p) != nil {
		return nil, errors.New("节点配置必须是 YAML 对象")
	}
	return p, nil
}
func identity(p Proxy) (string, error) {
	copy := Proxy{}
	for key, value := range p {
		if key != "name" && key != "_source" {
			copy[key] = value
		}
	}
	encoded, err := json.Marshal(copy)
	return string(encoded), err
}
func uniqueName(name string, occupied map[string]bool) string {
	if !occupied[name] {
		return name
	}
	for n := 2; ; n++ {
		candidate := fmt.Sprintf("%s-%d", name, n)
		if !occupied[candidate] {
			return candidate
		}
	}
}

var ruleTarget = regexp.MustCompile(`,([^,]+?)(,no-resolve)?$`)
var countryPrefix = regexp.MustCompile(`^[\x{1F1E6}-\x{1F1FF}]{2} [^|\r\n]+ \| `)

func rewriteReferences(node *yaml.Node, renames map[string]string, ruleList bool) {
	if len(renames) == 0 {
		return
	}
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, child := node.Content[i].Value, node.Content[i+1]
			if (key == "dialer-proxy" || key == "proxy") && child.Kind == yaml.ScalarNode {
				if name, ok := renames[child.Value]; ok {
					child.Value = name
				}
				continue
			}
			if key == "proxies" && child.Kind == yaml.SequenceNode {
				var values []*yaml.Node
				seen := map[string]bool{}
				for _, entry := range child.Content {
					if entry.Kind == yaml.ScalarNode {
						if name, ok := renames[entry.Value]; ok {
							entry.Value = name
						}
						if seen[entry.Value] {
							continue
						}
						seen[entry.Value] = true
					}
					values = append(values, entry)
				}
				child.Content = values
			}
			if key == "sub-rules" && child.Kind == yaml.MappingNode {
				for j := 1; j < len(child.Content); j += 2 {
					rewriteReferences(child.Content[j], renames, true)
				}
			} else {
				rewriteReferences(child, renames, key == "rules")
			}
		}
	case yaml.SequenceNode:
		for _, child := range node.Content {
			if ruleList && child.Kind == yaml.ScalarNode && !strings.HasPrefix(child.Value, "SUB-RULE,") {
				loc := ruleTarget.FindStringSubmatchIndex(child.Value)
				if loc != nil {
					target := child.Value[loc[2]:loc[3]]
					if name, ok := renames[target]; ok {
						child.Value = child.Value[:loc[2]] + name + child.Value[loc[3]:]
					}
				}
			} else {
				rewriteReferences(child, renames, false)
			}
		}
	}
}

func parseTemplate(input string) (*yaml.Node, *yaml.Node, error) {
	if strings.TrimSpace(input) == "" {
		return nil, nil, errors.New("请先加载或粘贴 YAML 模板")
	}
	var doc yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(input))
	if err := decoder.Decode(&doc); err != nil {
		return nil, nil, errors.New("YAML 解析失败，请检查缩进和字段格式")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, nil, errors.New("只支持包含一个文档的 YAML 模板")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("YAML 顶层必须是对象")
	}
	var check map[string]any
	if err := doc.Decode(&check); err != nil {
		return nil, nil, errors.New("YAML 存在重复键、无效别名或格式错误")
	}
	root := doc.Content[0]
	proxies := field(root, "proxies")
	if proxies == nil {
		proxies = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		setField(root, "proxies", proxies)
	}
	if proxies.Kind != yaml.SequenceNode {
		return nil, nil, errors.New("proxies 必须是节点数组")
	}
	groups := field(root, "proxy-groups")
	if groups != nil && groups.Kind != yaml.SequenceNode {
		return nil, nil, errors.New("proxy-groups 必须是数组")
	}
	occupied := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}
	if groups != nil {
		for _, group := range groups.Content {
			name := nodeText(field(group, "name"))
			if name == "" || occupied[name] {
				return nil, nil, errors.New("代理组名称为空或重复")
			}
			occupied[name] = true
			if list := field(group, "proxies"); list != nil {
				if list.Kind != yaml.SequenceNode {
					return nil, nil, errors.New("代理组 proxies 必须是数组")
				}
				for _, n := range list.Content {
					if n.Kind != yaml.ScalarNode {
						return nil, nil, errors.New("代理组引用必须是节点名称")
					}
				}
			}
		}
	}
	for _, n := range proxies.Content {
		p, err := proxyFromNode(n)
		if err != nil {
			return nil, nil, err
		}
		name := text(p["name"])
		if name == "" || occupied[name] {
			return nil, nil, errors.New("模板中存在节点重名或与代理组重名，请先修正名称")
		}
		occupied[name] = true
	}
	return &doc, root, nil
}

func decodeNodeList(input string) ([]Proxy, error) {
	var doc yaml.Node
	decoder := yaml.NewDecoder(strings.NewReader(input))
	if err := decoder.Decode(&doc); err != nil || len(doc.Content) != 1 {
		return nil, errors.New("节点 YAML 解析失败")
	}
	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("节点 YAML 只能包含一个文档")
	}
	var check any
	if err := doc.Decode(&check); err != nil {
		return nil, errors.New("节点 YAML 存在重复键或无效格式")
	}
	root := doc.Content[0]
	if root.Kind == yaml.MappingNode {
		root = field(root, "proxies")
	}
	if root == nil || root.Kind != yaml.SequenceNode {
		return nil, errors.New("节点 YAML 必须是数组，或包含 proxies 数组")
	}
	var nodes []Proxy
	for _, item := range root.Content {
		p, err := proxyFromNode(item)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, p)
	}
	return nodes, nil
}

func nodesOf(node *yaml.Node) []*yaml.Node {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	return node.Content
}

func renameYAML(input string, names []string) (string, error) {
	doc, root, err := parseTemplate(input)
	if err != nil {
		return "", err
	}
	proxies := field(root, "proxies")
	if len(names) != len(proxies.Content) {
		return "", errors.New("节点名称数量与节点列表不一致")
	}
	occupied := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true, "COMPATIBLE": true, "GLOBAL": true}
	for _, group := range nodesOf(field(root, "proxy-groups")) {
		occupied[nodeText(field(group, "name"))] = true
	}
	renamed := map[string]string{}
	for i, node := range proxies.Content {
		name := strings.TrimSpace(names[i])
		if name == "" {
			return "", errors.New("节点名称不能为空")
		}
		if strings.ContainsAny(name, ",\r\n\t") {
			return "", errors.New("节点名称不能包含逗号、换行或制表符，以免影响规则引用")
		}
		p, _ := proxyFromNode(node)
		old := text(p["name"])
		if occupied[name] {
			return "", fmt.Errorf("节点名称已被占用：%s", name)
		}
		if name != old {
			renamed[old] = name
		}
		occupied[name] = true
	}
	for i, node := range proxies.Content {
		field(node, "name").Value = strings.TrimSpace(names[i])
	}
	rewriteReferences(root, renamed, false)
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return "", errors.New("生成 YAML 失败")
	}
	_ = encoder.Close()
	return buffer.String(), nil
}

func Convert(ctx context.Context, req ConvertRequest) (ConvertResult, error) {
	r := ConvertResult{Warnings: []string{}, Nodes: []NodeSummary{}}
	doc, root, err := parseTemplate(req.Template)
	if err != nil {
		return r, err
	}
	proxies, groups := field(root, "proxies"), field(root, "proxy-groups")
	var incoming []Proxy
	var firstUnsupported error
	for index, line := range strings.Split(req.Links, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := ParseLink(line)
		if err != nil {
			var unsupported *UnsupportedTransportError
			if errors.As(err, &unsupported) {
				warning := fmt.Errorf("分享链接第 %d 行已跳过：%w", index+1, err)
				if firstUnsupported == nil {
					firstUnsupported = warning
				}
				r.Unsupported++
				r.Warnings = append(r.Warnings, warning.Error())
				continue
			}
			return r, fmt.Errorf("分享链接第 %d 行：%w", index+1, err)
		}
		incoming = append(incoming, p)
	}
	if strings.TrimSpace(req.NodesYAML) != "" {
		nodes, err := decodeNodeList(req.NodesYAML)
		if err != nil {
			return r, err
		}
		req.Nodes = append(req.Nodes, nodes...)
	}
	for _, p := range req.Nodes {
		clean := Proxy{}
		for k, v := range p {
			if !strings.HasPrefix(k, "_") {
				clean[k] = v
			}
		}
		if text(clean["type"]) == "" || !validServer(text(clean["server"])) {
			return r, errors.New("待导入节点缺少协议或有效服务器地址")
		}
		if strings.EqualFold(text(clean["network"]), "quic") {
			return r, &UnsupportedTransportError{Protocol: text(clean["type"]), Network: "quic"}
		}
		switch text(clean["type"]) {
		case "vmess", "vless", "tuic":
			if text(clean["uuid"]) == "" {
				return r, errors.New("待导入节点缺少 UUID")
			}
		case "trojan", "hysteria2", "anytls", "ss":
		default:
			return r, errors.New("待导入节点的协议暂不支持")
		}
		if kind := text(clean["type"]); kind != "vmess" && kind != "vless" && text(clean["password"]) == "" {
			return r, errors.New("待导入节点缺少密码")
		}
		if text(clean["type"]) == "ss" && text(clean["cipher"]) == "" {
			return r, errors.New("Shadowsocks 节点缺少加密方法 cipher")
		}
		port, err := portNumber(clean["port"])
		if err != nil {
			return r, err
		}
		clean["port"] = port
		if text(clean["name"]) == "" {
			clean["name"] = strings.ToUpper(text(clean["type"])) + "-" + text(clean["server"])
		}
		incoming = append(incoming, clean)
	}
	if firstUnsupported != nil && len(incoming) == 0 {
		return r, firstUnsupported
	}
	if req.Servers != "" {
		servers, err := splitServers(req.Servers)
		if err != nil {
			return r, err
		}
		if len(incoming) == 0 {
			return r, errors.New("批量替换 IP 需要先导入节点 YAML 或提供分享链接")
		}
		var expanded []Proxy
		for _, server := range servers {
			for _, p := range incoming {
				clone := Proxy{}
				for k, v := range p {
					clone[k] = v
				}
				clone["server"] = server
				clone["name"] = countryPrefix.ReplaceAllString(text(p["name"]), "") + " @ " + server
				expanded = append(expanded, clone)
			}
		}
		incoming = expanded
	}
	if len(incoming)+len(proxies.Content) > 1000 {
		return r, errors.New("一次转换最多处理 1000 个节点")
	}
	if req.Options.CleanExisting {
		for {
			seen := map[string]string{}
			renames := map[string]string{}
			var kept []*yaml.Node
			for _, n := range proxies.Content {
				p, _ := proxyFromNode(n)
				id, err := identity(p)
				if err != nil {
					return r, errors.New("节点包含无法比较的配置字段")
				}
				name := text(p["name"])
				if old, ok := seen[id]; ok {
					renames[name] = old
					r.Removed++
				} else {
					seen[id] = name
					kept = append(kept, n)
				}
			}
			proxies.Content = kept
			if len(renames) == 0 {
				break
			}
			rewriteReferences(root, renames, false)
		}
	}
	occupied, configs := map[string]bool{}, map[string]bool{}
	for _, name := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL"} {
		occupied[name] = true
	}
	if groups != nil {
		for _, group := range groups.Content {
			occupied[nodeText(field(group, "name"))] = true
		}
	}
	for _, n := range proxies.Content {
		p, _ := proxyFromNode(n)
		id, err := identity(p)
		if err != nil {
			return r, errors.New("节点配置无法比较")
		}
		configs[id] = true
		occupied[text(p["name"])] = true
	}
	lookup := NewCountryLookup()
	if req.Options.Country && req.Options.MarkExisting {
		renames := map[string]string{}
		for _, n := range proxies.Content {
			p, _ := proxyFromNode(n)
			old := text(p["name"])
			name := lookup.Label(ctx, old, text(p["server"]))
			if name != old {
				delete(occupied, old)
				name = uniqueName(name, occupied)
				occupied[name] = true
				field(n, "name").Value = name
				renames[old] = name
				r.Labeled++
			}
		}
		rewriteReferences(root, renames, false)
		// Referenced proxy names can change during labeling; refresh content identities.
		configs = map[string]bool{}
		for _, n := range proxies.Content {
			p, _ := proxyFromNode(n)
			id, _ := identity(p)
			configs[id] = true
		}
	}
	var addedNames []string
	for _, p := range incoming {
		id, err := identity(p)
		if err != nil {
			return r, errors.New("节点配置无法比较")
		}
		if configs[id] {
			r.Skipped++
			continue
		}
		name := text(p["name"])
		if req.Options.Country {
			labeled := lookup.Label(ctx, name, text(p["server"]))
			if labeled != name {
				r.Labeled++
			}
			name = labeled
		}
		p["name"] = uniqueName(name, occupied)
		n := &yaml.Node{}
		if err := n.Encode(p); err != nil {
			return r, errors.New("节点无法转换为 YAML")
		}
		proxies.Content = append(proxies.Content, n)
		addedNames = append(addedNames, text(p["name"]))
		occupied[text(p["name"])], configs[id] = true, true
		r.Added++
	}
	if groups != nil {
		r.Groups = len(groups.Content)
		if req.Options.SyncGroups {
			for _, group := range groups.Content {
				list := field(group, "proxies")
				if list == nil {
					continue
				}
				seen := map[string]bool{}
				var kept []*yaml.Node
				for _, n := range list.Content {
					if !seen[n.Value] {
						kept = append(kept, n)
						seen[n.Value] = true
					}
				}
				list.Content = kept
				for _, name := range addedNames {
					if !seen[name] {
						list.Content = append(list.Content, scalar(name))
						seen[name] = true
					}
				}
			}
		}
	}
	for _, n := range proxies.Content {
		p, _ := proxyFromNode(n)
		port, _ := portNumber(p["port"])
		transport := first(text(p["network"]), "tcp")
		if text(p["type"]) == "tuic" || text(p["type"]) == "hysteria2" {
			transport = "udp / quic"
		}
		if object(p["ws-opts"])["v2ray-http-upgrade"] == true {
			transport = "httpupgrade"
		}
		r.Nodes = append(r.Nodes, NodeSummary{text(p["name"]), text(p["type"]), text(p["server"]), port, transport})
	}
	r.Total = len(proxies.Content)
	r.Warnings = append(r.Warnings, lookup.Warnings...)
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(doc); err != nil {
		return r, errors.New("生成 YAML 失败")
	}
	_ = encoder.Close()
	r.YAML = buffer.String()
	return r, nil
}
