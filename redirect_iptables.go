//go:build linux

package tun

import (
	"fmt"
	"os/exec"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/ranges"
)

func (r *autoRedirect) setupIPTables() error {
	if r.routeExcludeAddressSet != nil && len(*r.routeExcludeAddressSet) > 0 {
		r.iptablesSetupIPSet()
	}
	if r.enableIPv4 {
		if err := r.setupIPTablesForFamily(r.iptablesPath, false); err != nil {
			return E.Cause(err, "setup iptables")
		}
	}
	if r.enableIPv6 {
		if err := r.setupIPTablesForFamily(r.ip6tablesPath, true); err != nil {
			return E.Cause(err, "setup ip6tables")
		}
	}
	return nil
}

func (r *autoRedirect) setupIPTablesForFamily(iptablesPath string, isIPv6 bool) error {
	redirectPort := r.redirectPort()
	outputMark := r.effectiveOutputMark()
	resetMark := r.effectiveResetMark()
	nfQueue := r.effectiveNFQueue()

	tableNamePrerouting := r.tableName + "-prerouting"
	tableNameOutput := r.tableName + "-output"
	tableNamePreMatch := r.tableName + "-prematch"
	tableNamePreMatchOut := r.tableName + "-prematch-out"

	ipsetName := r.tableName + "-excl"
	if isIPv6 {
		ipsetName += "6"
	}

	routeExcludeAddress := r.tunOptions.Inet4RouteExcludeAddress
	if isIPv6 {
		routeExcludeAddress = r.tunOptions.Inet6RouteExcludeAddress
	}

	// mangle PREROUTING: nfqueue pre-match for bypass action
	if r.nfqueueEnabled {
		if err := r.runShell(iptablesPath, "-t mangle -N", tableNamePreMatch); err != nil {
			return err
		}
		_ = r.runShell(iptablesPath, "-t mangle -A", tableNamePreMatch, "-i", r.tunOptions.Name, "-j RETURN")
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -m mark --mark 0x%08x -j CONNMARK --save-mark", tableNamePreMatch, outputMark))
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -m mark --mark 0x%08x -j RETURN", tableNamePreMatch, outputMark))
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -m mark --mark 0x%08x -j REJECT --reject-with tcp-reset", tableNamePreMatch, resetMark))
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -m connmark --mark 0x%08x -j RETURN", tableNamePreMatch, outputMark))
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -p tcp --syn -j NFQUEUE --queue-num %d --queue-bypass", tableNamePreMatch, nfQueue))
		if err := r.runShell(iptablesPath, "-t mangle -I PREROUTING -j", tableNamePreMatch); err != nil {
			return err
		}
	}

	// nat PREROUTING: redirect hotspot/downstream traffic
	if err := r.runShell(iptablesPath, "-t nat -N", tableNamePrerouting); err != nil {
		return err
	}
	if r.nfqueueEnabled {
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t nat -A %s -m connmark --mark 0x%08x -j RETURN", tableNamePrerouting, outputMark))
	}
	_ = r.runShell(iptablesPath, "-t nat -A", tableNamePrerouting, "-i", r.tunOptions.Name, "-j RETURN")
	for _, prefix := range routeExcludeAddress {
		_ = r.runShell(iptablesPath, "-t nat -A", tableNamePrerouting, "-d", prefix.String(), "-j RETURN")
	}
	if r.ipsetEnabled {
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t nat -A %s -m set --match-set %s dst -j RETURN", tableNamePrerouting, ipsetName))
	}
	for _, addr := range r.localAddresses {
		if addr.Addr().Is6() == isIPv6 {
			_ = r.runShell(iptablesPath, "-t nat -A", tableNamePrerouting, "-d", addr.String(), "-j RETURN")
		}
	}
	if err := r.runShell(iptablesPath, fmt.Sprintf("-t nat -A %s -p tcp -j REDIRECT --to-ports %d", tableNamePrerouting, redirectPort)); err != nil {
		return err
	}
	if err := r.runShell(iptablesPath, "-t nat -I PREROUTING -j", tableNamePrerouting); err != nil {
		return err
	}

	if r.shouldSkipOutputChain() {
		return nil
	}

	// mangle OUTPUT: nfqueue pre-match for local machine traffic
	if r.nfqueueEnabled {
		if err := r.runShell(iptablesPath, "-t mangle -N", tableNamePreMatchOut); err != nil {
			return err
		}
		_ = r.runShell(iptablesPath, "-t mangle -A", tableNamePreMatchOut, "-o", r.tunOptions.Name, "-j RETURN")
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -m mark --mark 0x%08x -j CONNMARK --save-mark", tableNamePreMatchOut, outputMark))
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -m mark --mark 0x%08x -j RETURN", tableNamePreMatchOut, outputMark))
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -m mark --mark 0x%08x -j REJECT --reject-with tcp-reset", tableNamePreMatchOut, resetMark))
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -m connmark --mark 0x%08x -j RETURN", tableNamePreMatchOut, outputMark))
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t mangle -A %s -p tcp --syn -j NFQUEUE --queue-num %d --queue-bypass", tableNamePreMatchOut, nfQueue))
		if err := r.runShell(iptablesPath, "-t mangle -I OUTPUT -j", tableNamePreMatchOut); err != nil {
			return err
		}
	}

	// nat OUTPUT: redirect local machine's own traffic
	if err := r.runShell(iptablesPath, "-t nat -N", tableNameOutput); err != nil {
		return err
	}
	if r.nfqueueEnabled {
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t nat -A %s -m connmark --mark 0x%08x -j RETURN", tableNameOutput, outputMark))
	}
	for _, uidRange := range r.tunOptions.ExcludeUID {
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t nat -A %s -m owner --uid-owner %s -j RETURN", tableNameOutput, formatUIDRange(uidRange)))
	}
	for _, prefix := range routeExcludeAddress {
		_ = r.runShell(iptablesPath, "-t nat -A", tableNameOutput, "-d", prefix.String(), "-j RETURN")
	}
	if r.ipsetEnabled {
		_ = r.runShell(iptablesPath, fmt.Sprintf("-t nat -A %s -m set --match-set %s dst -j RETURN", tableNameOutput, ipsetName))
	}
	if err := r.runShell(iptablesPath, fmt.Sprintf("-t nat -A %s -p tcp -o %s -j REDIRECT --to-ports %d", tableNameOutput, r.tunOptions.Name, redirectPort)); err != nil {
		return err
	}
	if err := r.runShell(iptablesPath, "-t nat -I OUTPUT -j", tableNameOutput); err != nil {
		return err
	}
	return nil
}

func formatUIDRange(r ranges.Range[uint32]) string {
	if r.Start == r.End {
		return fmt.Sprintf("%d", r.Start)
	}
	return fmt.Sprintf("%d-%d", r.Start, r.End)
}

func (r *autoRedirect) cleanupIPTables() {
	if r.enableIPv4 {
		r.cleanupIPTablesForFamily(r.iptablesPath)
	}
	if r.enableIPv6 {
		r.cleanupIPTablesForFamily(r.ip6tablesPath)
	}
	r.iptablesCleanupIPSet()
}

func (r *autoRedirect) cleanupIPTablesForFamily(iptablesPath string) {
	tableNamePrerouting := r.tableName + "-prerouting"
	tableNameOutput := r.tableName + "-output"
	tableNamePreMatch := r.tableName + "-prematch"
	tableNamePreMatchOut := r.tableName + "-prematch-out"

	_ = r.runShell(iptablesPath, "-t mangle -D PREROUTING -j", tableNamePreMatch)
	_ = r.runShell(iptablesPath, "-t mangle -F", tableNamePreMatch)
	_ = r.runShell(iptablesPath, "-t mangle -X", tableNamePreMatch)
	_ = r.runShell(iptablesPath, "-t mangle -D OUTPUT -j", tableNamePreMatchOut)
	_ = r.runShell(iptablesPath, "-t mangle -F", tableNamePreMatchOut)
	_ = r.runShell(iptablesPath, "-t mangle -X", tableNamePreMatchOut)
	_ = r.runShell(iptablesPath, "-t nat -D PREROUTING -j", tableNamePrerouting)
	_ = r.runShell(iptablesPath, "-t nat -F", tableNamePrerouting)
	_ = r.runShell(iptablesPath, "-t nat -X", tableNamePrerouting)
	_ = r.runShell(iptablesPath, "-t nat -D OUTPUT -j", tableNameOutput)
	_ = r.runShell(iptablesPath, "-t nat -F", tableNameOutput)
	_ = r.runShell(iptablesPath, "-t nat -X", tableNameOutput)
}

func (r *autoRedirect) iptablesSetupIPSet() {
	if r.routeExcludeAddressSet == nil {
		return
	}
	if !r.probeXTSet() {
		r.logger.Warn("xt_set not available, route_exclude_address_set falls back to per-prefix rules (slow for large sets)")
		return
	}
	name4 := r.tableName + "-excl"
	name6 := name4 + "6"
	_ = r.runShell("ipset", "create", name4, "hash:net", "family", "inet", "maxelem", "2000000", "-exist")
	_ = r.runShell("ipset", "flush", name4)
	_ = r.runShell("ipset", "create", name6, "hash:net", "family", "inet6", "maxelem", "500000", "-exist")
	_ = r.runShell("ipset", "flush", name6)
	for _, set := range *r.routeExcludeAddressSet {
		for _, prefix := range set.Prefixes() {
			if prefix.Addr().Is4() {
				_ = r.runShell("ipset", "add", name4, prefix.String(), "-exist")
			} else {
				_ = r.runShell("ipset", "add", name6, prefix.String(), "-exist")
			}
		}
	}
	r.ipsetEnabled = true
}

func (r *autoRedirect) iptablesUpdateIPSet() {
	if !r.ipsetEnabled || r.routeExcludeAddressSet == nil {
		return
	}
	name4 := r.tableName + "-excl"
	name6 := name4 + "6"
	_ = r.runShell("ipset", "flush", name4)
	_ = r.runShell("ipset", "flush", name6)
	for _, set := range *r.routeExcludeAddressSet {
		for _, prefix := range set.Prefixes() {
			if prefix.Addr().Is4() {
				_ = r.runShell("ipset", "add", name4, prefix.String(), "-exist")
			} else {
				_ = r.runShell("ipset", "add", name6, prefix.String(), "-exist")
			}
		}
	}
}

func (r *autoRedirect) iptablesCleanupIPSet() {
	name4 := r.tableName + "-excl"
	name6 := name4 + "6"
	_ = r.runShell("ipset", "flush", name4)
	_ = r.runShell("ipset", "destroy", name4)
	_ = r.runShell("ipset", "flush", name6)
	_ = r.runShell("ipset", "destroy", name6)
}

func (r *autoRedirect) probeXTSet() bool {
	probeName := r.tableName + "-xtprobe"
	if err := r.runShell("ipset", "create", probeName, "hash:net", "family", "inet", "-exist"); err != nil {
		return false
	}
	defer func() { _ = r.runShell("ipset", "destroy", probeName) }()
	return r.runShell(r.iptablesPath,
		fmt.Sprintf("-t nat -C OUTPUT -m set --match-set %s dst -j RETURN", probeName)) == nil
}

func (r *autoRedirect) runShell(commands ...any) error {
	commandStr := strings.Join(F.MapToString(commands), " ")
	var command *exec.Cmd
	if r.androidSu {
		command = exec.Command(r.suPath, "-c", commandStr)
	} else {
		commandArray := strings.Split(commandStr, " ")
		command = exec.Command(commandArray[0], commandArray[1:]...)
	}
	combinedOutput, err := command.CombinedOutput()
	if err != nil {
		return E.Extend(err, F.ToString(commandStr, ": ", string(combinedOutput)))
	}
	return nil
}