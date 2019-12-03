import os, sys, logging, Ice, traceback

log = logging.getLogger("CS118")
logging.basicConfig(stream=sys.stderr)
log.setLevel(logging.DEBUG)

slice_dir = Ice.getSliceDir()
if not slice_dir:
    log.error(sys.argv[0] + ': Slice directory not found.')
    sys.exit(1)

Ice.loadSlice("", ["-I%s" % slice_dir, "core/pox.ice"])
import pox

class Client(Ice.Application):
    def run(self, args):

        base = self.communicator().stringToProxy("Tester:tcp -h 127.0.0.1 -p 65500")
        tester = pox.TesterPrx.checkedCast(base)
        if not tester:
            raise RuntimeError("Invalid proxy")

        if len(args) < 2 or args[1] == "arp":
            print(tester.getArp())
        else:
            print(tester.getRoutingTable())
        return 0
 
app = Client()
status = app.main(sys.argv)
sys.exit(status)
