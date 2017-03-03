#! /usr/bin/python

INTERFACE_CHOICES=[u'wlan0', u'wlan1', u'eth0', u'eth1', u'lo']

def parseargs():
    """Parse the arguments"""
    import argparse
    parser = argparse.ArgumentParser(description='Alter the state of a given interface.', epilog='Basicly a python wrapper for iface.')
    parser.add_argument('-i', '--interface', default=INTERFACE_CHOICES[1], choices=INTERFACE_CHOICES, help='The interface to use.')
	the_action = parser.add_mutually_exclusive_group(required=True)
    the_action.add_argument('-u', '--up', '--enable', dest='enable_action', default=False, help='Enable the given interface.')
    the_action.add_argument('-d', '--down', '--disable', dest='disable_action', default=False, help='Disable the given interface.')
    the_action.add_argument('-r', '--down-up', '--restart', dest='restart_action', default=True, help='Disable and then re-enable the given interface. (default)')
    theResult = parser.parse_args()
    return theResult


def taint_name(rawtxt):
    """check the interface arguments"""
    if rawtxt.lower() in "wlan1":
        return u'wlan1'
    elif rawtxt.lower() in "wlan0":
        return u'wlan0'
    elif rawtxt.lower() in "eth0":
        return u'eth0'
    elif rawtxt.lower() in "eth1":
        return u'eth1'
    elif rawtxt.lower() in "lo":
        return u'lo'
    else:
        return None

def enable_iface(iface_name="lo"):
    """enable the given interface by calling ifup."""
    tainted_name = taint_name(iface_name)
    import subprocess
    theResult = subprocess.check_output(['ifup', tainted_name])
    return theResult

def disable_iface(iface_name="lo", force=False):
    """disable the given interface by calling ifdown."""
    tainted_name = taint_name(iface_name)
    import subprocess
    if force is False:
        theResult = subprocess.check_output(['ifdown', tainted_name])
    elif force is True:
        theResult = subprocess.check_output(['ifdown', '--force', tainted_name])
    return theResult

def restart_iface(iface_name="lo"):
    """Disable the given interface by calling ifdown, THEN re-enable the given interface by calling ifup."""
    tainted_name = taint_name(iface_name)
    disable_iface(tainted_name, True)
    enable_iface(tainted_name)
    return True

if __name__ == '__main__':
    args = parseargs()
    try:
        interface = args.interface
        if args.enable_action is True:
            enable_iface(interface)
            exit(0)
        elif args.disable_action is True:
            disable_iface(interface, False)
            exit(0)
        elif args.restart_action is True:
            restart_iface(interface)
            exit(0)
    except Exception as main_err:
        print(str("iface_pwr_mgr: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"))
        print(str(main_err.args[0]))
exit(1)
