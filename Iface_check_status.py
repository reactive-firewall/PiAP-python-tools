#! /usr/bin/python

INTERFACE_CHOICES=[u'wlan0', u'wlan1', u'eth0', u'eth1', u'lo']

def parseargs():
    """Parse the arguments"""
    import argparse
    try:
        parser = argparse.ArgumentParser(description='Report the state of a given interface.', epilog='Basicly a python wrapper for ip show.')
        parser.add_argument('-i', '--interface', default=INTERFACE_CHOICES[1], choices=INTERFACE_CHOICES, help='The interface to use.')
	    the_action = parser.add_mutually_exclusive_group(required=True)
        the_action.add_argument('-v', '--verbose', dest='verbose_mode', default=False, help='Enable verbose mode.')
        the_action.add_argument('-q', '--quiet', dest='verbose_mode', default=False, help='Disable the given interface.')
        theResult = parser.parse_args()
    except Exception as parseErr:
        parser.error(str(parseErr))
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

def show_iface(iface_name="lo"):
    """enable the given interface by calling ifup."""
    tainted_name = taint_name(iface_name)
    import subprocess
    theResult = subprocess.check_output(['ip', 'addr', 'show', tainted_name])
    return theResult

if __name__ == '__main__':
    args = parseargs()
    try:
        interface = args.interface
        if args.verbose_mode is True:
            print(show_iface(interface))
            exit(0)
        elif args.disable_action is True:
            status_txt = show_iface(interface)
            if ("DOWN" in status_txt):
                print("inactive")
            elif (" UP" in status_txt):
                print("active")
            exit(0)
    except Exception as main_err:
        print(str("iface_check_status: REALLY BAD ERROR: ACTION will not be compleated! ABORT!"))
        print(str(main_err.args[0]))
exit(1)
