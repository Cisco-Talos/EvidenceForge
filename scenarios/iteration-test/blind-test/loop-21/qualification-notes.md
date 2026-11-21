# Unselected directory-stat follow-up — read-only qualification

17Host noted identical directory stat shape. PublicOS-only native stat plus immediate
entry COUNTS (no names/contents/homes/thirdparty enumeration)onmacOS27.2.1arm64:
/entries23,nlink23,size736; /bin37/39/1248; /sbin72/74/2368;
/usr/bin934/936/29952; TerminalContents/MacOS1/3/96. Allblocks0.
Observed size=32*nlink in this bounded sample. Ordinarydirnlink=entries+2, root
presentation differs. DO NOT promote this to a universal law or equate on-disk
APFSnchildren/nlink union with stat.st_nlink. AppleAPFSReference pp75–76documents
nchildren fordirectoryentries vsnlinkfornondirectory hardlinks, but notthisstat
size mapping. Needs morequalification beforeproductionpolicy. Sourceexample retained.

Potential owner is shared canonical directory population/provisioning, notrenderer.
A repair should derive native stat from coherent modeled directory membership /
roles and snapshot times, rather than randomizing independent fields or adding
more display templates. Exactroot2adapter19alone doesnotfix population/timestamps.
System file snapshot birth cohorts/highinode namespace also remain separate larger
provisioning work. Sharedpresentedst_dev acrossSystem/data is valid(nativeexample19).
No21selection/contract/code yet. Waitactual20findings and keep30loopbenchmarkfixed.
Primarysource https://developer.apple.com/support/downloads/Apple-File-System-Reference.pdf
