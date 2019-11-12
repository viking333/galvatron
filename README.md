# galvatron (because yeah transformers!)
Tools for assessing third-party software

## Why?
I review lots of third party software and library code to assess the risk of
introducing the software into the environment. Part of this is code review of
libraries, cve searches, virus scans and just straight up just checking the
network traffic a piece of software sends out

## Approach
Not all of these tasks were required on every single piece of software evaluated
so I wanted a way to pick and choose what I did. Some level of automation was
potentially required and I wanted a familiar workflow. Being a hacker /
pentester / dev I decided to write this from scratch in python based of the Cmd
module (awesome module by the way). I then realised that
[Recon-NG](https://github.com/lanmaster53/recon-ng) did all this and was an
awesome fit so.........I decided to grab a copy make the DB structure my own and
write my own modules! I think it worked out great but go checkout Recon-NG its
awesome.

## Install
Clone repo and install the module_requirements file (pip2 -r yada yada yada). If
you get some problems with the core see the Recon-NG requirements file

## Workflow
1. Set up workspace `workspaces add my_workspace`
2. Add a target `add targets` this will ask you for a path to the exe tar gz
   file etc (also accepts git repo urls that end in .git). It also auto unpacks
   archives where it can
3. Choose your module `use code_qa/grep_bugs` for example will go through the
   unpacked source code for files it has regexes for and report them in the
   qa_issues table (for you to review)
4. Decide if you wanna use the piece of crap you're looking at

You can run as many modules as many times as you like (its idempotent) and cause
the core is Recon-NG you have the other provided goodies such as `show dashboard` 
and automation by providing a list of commands in a resource file (again see
recon-ng)

## Capture Traffic Module
This probably needs renaming but it does the following
1. Restores a snapshot on a vm (configured in the options `show options`)
2. Sets up dnsmaq on the host network adapter (virtualbox network should have
   dhcp server disabled and the vm should only have host only network enabled)
3. Runs mitmdump listening for traffic
4. Uses iptables to route incoming traffic to the internet through mitmdump
   transparently
5. Installs the mitmproxy root cert into the windows certificate store
6. Copies the target binary etc to the \galvatron folder on the target
7. When you're done (Ctrl-C out of the proxy) and it will pull all the HTTP data
   out and store in DB. It will also run a Attack Surface Analyzer scan and
   compare with a scan called baseline and process the results.

_Module Requirements_
- Install `libxslt-dev`, `libxml2-dev` and `dnsmasq` via apt
- Install mitmproxy using pip3
- As dnsmasq uses the same port as local DNS stub listener, we need to disable it using `systemctl stop systemd-resolved`

_VM Requirements_
- Needs to be on a host only network (no nat interfaces) 
- have a \galvatron folder in root of C
- Have Atack Surface Analyzer in the \gavatron (rename folder to asa and rename
  ASALaunch.bat to asa.bat)
- Run a scan `cd \galvatron\asa && .\asa.bat collect --runid baseline --all`
- Snapshot the machine after scan is complete

A regular windows install will create lots of noise so you may want to turn this
down a bit by
- Disable windows updates
- Turn off non essential services and scheduled tasks (i remove all the tasks)
You get the point.

Try stuff, read the code (excuse my shitty code). Some things are janky AF and
named wierd but hey thats life.

