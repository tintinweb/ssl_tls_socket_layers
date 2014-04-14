def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

def hexdump_squashed(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        if hxdat == "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00":
            if allnulls == 1:
                continue
            hxdat = '...'
            allnulls = 1
            pdat = ''
        else:
            pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
            allnulls = 0
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print 