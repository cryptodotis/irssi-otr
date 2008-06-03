#!/usr/bin/python
#
# Uli Meis <a.sporto+bee@gmail.com>
#
# Just a short script to generate our FORMAT_REC
#

import sys,os,re

lines = map(lambda x: x.strip(),open(sys.argv[1],"r").readlines())

hdr = open("otr-formats.h","w")
src = open("otr-formats.c","w")

src.write('#include "otr.h"\n');

src.write("""char *otr_help = "%s";\n""" % "\\n".join(
	["{hilight - OTR help -}"]+
	[re.sub('^(/otr.*)$','%_\\1%_',
		re.sub('"(.*)"','\\"%_\\1%_\\"',
			x.replace('\n','').replace("\t","        ") 
			))
		for x in open(sys.argv[2],"r").readlines()]+
	["{hilight - End of OTR help -}"]))

src.write('FORMAT_REC formats[] = {\n')

src.write('{ MODULE_NAME, "otr", 0}\n')

hdr.write("extern char *otr_help;\n\n");

hdr.write("enum {\n")

hdr.write("TXT_OTR_MODULE_NAME")

fills = 0

for line in lines:
	src.write(",\n")

	e = line.split("\t")

	if len(e)==1:
		# Section name
		src.write("""{ NULL, "%s", 0 }\n""" % (e[0]))

		hdr.write(",\nTXT_OTR_FILL_%d" % fills)
		
		fills += 1

		continue

	params = []
	fo = e[1]
	new = ""
	last=0
	i=0
	for m in re.finditer("(^|[^%])%[ds]",fo):
		if m.group()[-1]=='d':
			params += ['1']
		else:
			params += ['0']
		new += fo[last:m.start()+len(m.group(1))]+"$%d" % i
		last = m.end()
		i += 1

	new += fo[last:]

	e[1] = new
	e += [len(params)] + params

	#print "Handling line %s with elen %d" % (line,len(e))

	premsg = ""
	if e[1][0] != "{":
		premsg = "%9OTR%9: "

	src.write("""{ "%s", "%s%s", %s""" % (e[0],premsg,e[1],e[2]))

	if len(params)>0:
		src.write(", { %s }" % ", ".join(params))

	src.write("}")

	hdr.write(",\n")

	hdr.write("TXT_%s" % e[0].upper())

hdr.write("""
};

extern FORMAT_REC formats[];
""")

src.write(""",
{ NULL, NULL, 0 }
};
""")

hdr.close()
src.close()
