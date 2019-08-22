# -*- coding: utf-8 -*-
import subprocess
import time
import signal
import netifaces as ni
import os
import pexpect
import sys
from galvatron_lib.core.module import BaseModule
import json, itertools, tempfile


class Module(BaseModule):
    meta = {
            "name": "Captures HTTP Traffic from a VM",
            "author": "Mike West",
            "descrription": "Captures HTTP/HTTPS traffic from a VM",
            "query": "SELECT DISTINCT location, product_name, version FROM targets WHERE location IS NOT NULL",
            "options": [
                ["vm_name", "Windows 7", True, 'Name of the virtual machine to use'],
                ["interface", "", False, 'Interface to run proxy on'],
                ["snapshot", "Clean", True, 'Snapshot to restore'],
                ["vm_mode", "gui", True, 'startup mode of vm (gui or headless)'],
                ["admin_user", "", True, "Admin user of the VM"],
                ["admin_password", "", True, "Admin password of the admin user"]
            ]
    }

    def process_report(self, report_location, product, version):
        report = json.load(open(report_location))
        sections = ["files", "registry", "services", "users", "ports", "certs"]
        actions = ["add", "remove", "modify"]
        keys = ["{}_{}".format(x[0], x[1]) for x in itertools.product(sections, actions)]
        current_module = sys.modules[__name__]

        for k in keys:
            func, val_key = self.get_func(k, current_module)

            for v in report["results"][k]:
                data = func(v, val_key).rstrip("\n")
                if len(data) > 0:
                    object_type, action = k.split("_")
                    self.add_reported_change(product, version, object_type, action, data)

    def process_dict(self, old, new, key_name):
        old_keys = set(old.keys())
        new_keys = set(new.keys())

        diffs = u""
        for k in old.keys():
            if k in new and old[k] != new[k]:
                diffs += u"{}.{}: was {} is {}\n".format(key_name, k, old[k], new[k])

        for k in (new_keys - old_keys):
            diffs += u"{}.{}: added with value {}\n".format(key_name, k, new[k])

        for k in (old_keys - new_keys):
            diffs += u"{}.{}: removed\n".format(key_name, k)

        return diffs

    def process_list(self, old, new, key_name):
        tmp_old = set(old)
        tmp_new = set(new)
        diffs = u""
        if len(tmp_old - tmp_new) > 0: diffs += u" Removed: {}".format(", ".join(tmp_old - tmp_new))
        if len(tmp_new - tmp_old) > 0: diffs += u" Added: {}".format(", ".join(tmp_new - tmp_old))
        
        if len(diffs) > 0:
            diffs = u"{}:{}\n".format(key_name, diffs)

        return diffs

    def process_add_remove(self, f, val_key, action):
        diffs = u""
        if action == "Added": 
            src = "Compare" 
        else: 
            src = "Base"
        for k, v in f[src].iteritems():
            if isinstance(v, list): diffs += u"{}: {}\n".format(k, ", ".join(v))
            elif isinstance(v, dict):
                for l, m in v.iteritems():
                    diffs += "{}.{}: {}\n".format(k, l, m)
            else:
                diffs += "{}: {}\n".format(k, v)

        return diffs

    def process_remove(self, f, val_key):
        return self.process_add_remove(f, val_key, "Removed")

    def process_add(self, f, val_key):
        return self.process_add_remove(f, val_key, "Added")

    def process_modify(self, f, val_key):
        diffs = u"{}\n".format(f["Base"][val_key])
        for k in f["Base"].keys():
            if k == "RowKey": continue

            old, new = (f["Base"][k], f["Compare"][k])
            if isinstance(f["Base"][k], dict):
                diffs += self.process_dict(f["Base"][k], f["Compare"][k], k) 
            elif isinstance(f["Base"][k], list):
                diffs += self.process_list(f["Base"][k], f["Compare"][k], k)
            else: 
                if old != new:
                    diffs += u"{}: {} was {} is {}\n".format(f["Base"][val_key], k, old, new)
        
        return diffs.encode("ascii", "ignore")

    def get_valkey(self, key):
        if key.startswith("files"): return "Path"
        if key.startswith("registry"): return "Key"
        if key.startswith("services"): return "ServiceName"
        if key.startswith("users"): return "Name"
        if key.startswith("ports"): return "port"
        if key.startswith("certs"): return "Subject"

    def get_func(self, key, current_module):
        try:
            func = getattr(current_module, key)
        except:
            if "_modify" in key: func = self.process_modify
            if "_add" in key: func = self.process_add
            if "_remove" in key: func = self.process_remove

        return func, self.get_valkey(key)


    def get_ip(self, interface):
        ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
        return ip

    def teardown_iptables(self):
        self.output("Disabling IP Forwarding....")
        os.system("sudo sysctl -w net.ipv4.ip_forward=0")
        os.system("sudo sysctl -w net.ipv6.conf.all.forwarding=0")

        self.output("Clearing IP tables rules....")
        os.system("sudo iptables -t nat --line-numbers -L | grep REDIRECT | cut -d\" \" -f1 | tac | tr '\\n' '\\0' | xargs -0 -n1 sudo iptables -t nat -D PREROUTING ")

    def enable_proxy(self, interface):
        self.output("Enabling IP Forwarding....")
        os.system("sudo sysctl -w net.ipv4.ip_forward=1")
        os.system("sudo sysctl -w net.ipv6.conf.all.forwarding=1")

        self.output("Redirecting proxy to http/https traffic to 8080")
        os.system("sudo iptables -t nat -A PREROUTING -i %s -p tcp --dport 80 -j REDIRECT --to-port 8080" % interface)
        os.system("sudo iptables -t nat -A PREROUTING -i %s -p tcp --dport 443 -j REDIRECT --to-port 8080" % interface)

        self.output("Starting proxy...Press Ctrl-C to stop")
        os.system("mitmdump --showhost --mode=transparent -w /tmp/proxy_capture.cap")

    def perform_asa_scan(self, vm, user, password, tmp_file):
        try:
            self.output("Starting post install asa scan...")
            self.output("VBoxManage guestcontrol \"%s\" run --username %s --password %s --exe \"C:\\WINDOWS\\system32\\cmd.exe\" --wait-stdout  -- cmd /c 'cd \\galvatron\\asa && asa.bat collect --runid new --all'" % (vm, user, password))
            os.system("VBoxManage guestcontrol \"%s\" run --username %s --password %s --exe \"C:\\WINDOWS\\system32\\cmd.exe\" --wait-stdout  -- cmd /c 'cd \\galvatron\\asa && asa.bat collect --runid new --all'" % (vm, user, password))

            self.output("Comparing baseline with new scan")
            self.output("VBoxManage guestcontrol \"%s\" run --username %s --password %s --exe \"C:\\WINDOWS\\system32\\cmd.exe\" --wait-stdout -- cmd /c 'cd \\galvatron\\asa && asa.bat export-collect --firstrunid baseline --secondrunid new --outputpath c:\\galvatron'" % (vm, user, password))
            os.system("VBoxManage guestcontrol \"%s\" run --username %s --password %s --exe \"C:\\WINDOWS\\system32\\cmd.exe\" --wait-stdout -- cmd /c 'cd \\galvatron\\asa && asa.bat export-collect --firstrunid baseline --secondrunid new --outputpath c:\\galvatron'" % (vm, user, password))
            os.system("VBoxManage guestcontrol \"%s\" copyfrom --username %s --password %s /galvatron/baseline_vs_new_summary.json.txt %s" % (vm, user, password, tmp_file))
        except:
            self.error("Error processing asa scan")

    def process_proxy_results(self, product, version):
        url_script = os.path.join(self.data_path, "capture_script.py")
        proc = subprocess.Popen(["mitmdump -q -nr /tmp/proxy_capture.cap -s " + url_script], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
        i = 1

        method = ""
        url = ""
        data = ""

        for l in iter(proc.stdout.readline, ''):
            instance = i % 3
            if instance == 1:
                method = l.rstrip("\n")
            elif instance == 2:
                url = l.rstrip("\n")
            else: 
                data = l.rstrip("\n")
                self.add_url(product, version, method, url, data)

            i = i + 1

    def setup_vm(self, vm, snapshot, mode):
        self.output("Restoring snapshot %s on %s" % (snapshot, vm))
        cmd = subprocess.call("VBoxManage snapshot \"%s\" restore \"%s\"" % (vm, snapshot), shell=True)

        self.output("Starting VM: %s" % vm)
        cmd = subprocess.call("VBoxManage startvm \"%s\" --type %s" % (vm, mode), shell=True)
        self.output("Giving VM time to wake up...")
        time.sleep(5)

    def get_interface(self, vm, interface):
        if interface == "":
            proc = subprocess.Popen(["VBoxManage showvminfo \"%s\" --machinereadable | grep hostonlyadapter" % vm], stdout = subprocess.PIPE, shell=True)
            interface = proc.communicate()[0].split("=")[1].rstrip().replace("\"", "")
            self.output("Interface not specified so using first host only interface found: %s" % interface)

        return interface

    def setup_dnsmasq(self, server_ip, interface):
        dhcp_range_prefix = ".".join(server_ip.split(".")[0:3])
        dhcp_range = dhcp_range_prefix + ".101," + dhcp_range_prefix + ".110"
        self.output("Staring dnsmasq with dhcp range: %s" % dhcp_range)
        dnsmasq = os.system("sudo dnsmasq -i %s --dhcp-range=%s" % (interface, dhcp_range))

    def install_root_cert(self, vm, user, password):
        self.output("Installing proxy root ca cert")
        os.system("VBoxManage guestcontrol \"%s\" mkdir --username %s --password %s /galvatron" % (vm, user, password))
        os.system("VBoxManage guestcontrol \"%s\" copyto --username %s --password %s --target-directory \"/galvatron/\" ~/.mitmproxy/mitmproxy-ca-cert.cer" % (vm, user, password))
        os.system("VBoxManage guestcontrol \"%s\" start --username %s --password %s --exe \"C:\\WINDOWS\\system32\\WindowsPowerShell\\v1.0\\powershell.exe\" -- powershell.exe -Command \"Start-Process 'cmd' -ArgumentList ('/c', 'certutil.exe -addstore Root c:\\galvatron\\mitmproxy-ca-cert.cer') -Verb RunAs\"" % (vm, user, password))

    def copy_file_to_machine(self, vm, user, password, exe):
        os.system("VBoxManage guestcontrol \"%s\" mkdir --username %s --password %s /galvatron" % (vm, user, password))
        self.output("Copying target to the \\galvatron folder on the VM")
        os.system("VBoxManage guestcontrol \"%s\" copyto --username %s --password %s --target-directory \"/galvatron/\" %s" % (vm, user, password, exe))

    def module_run(self, params):
        vm = self.options['vm_name']
        interface = self.options['interface']
        snapshot = self.options['snapshot']
        mode = self.options["vm_mode"]
        user = self.options["admin_user"]
        password = self.options["admin_password"]

        self.setup_vm(vm, snapshot, mode)
        self.install_root_cert(vm, user, password)

        dest_path = ""
        dnsmasq = None
        for location, product, version in params:
            self.copy_file_to_machine(vm, user, password, location)

        try:
            interface = self.get_interface(vm, interface)
            server_ip = self.get_ip(interface)
            self.output("Server ip found: %s" % server_ip)
            
            self.setup_dnsmasq(server_ip, interface)
            
            self.output("Press Ctrl-C to end capture")
            self.enable_proxy(interface)
            self.process_proxy_results(product, version)
        finally:
            report_filename = os.path.join(tempfile.mkdtemp(), 'report.tmp')
            self.perform_asa_scan(vm, user, password, report_filename)
            self.process_report(report_filename, product, version)
            self.output("Shutting down dnsmasq...")
            os.system("sudo killall dnsmasq")

            self.output("Shutting down VM: %s..." %vm)
            subprocess.call("VBoxManage controlvm \"%s\" poweroff" % vm, shell=True)

            self.teardown_iptables()
