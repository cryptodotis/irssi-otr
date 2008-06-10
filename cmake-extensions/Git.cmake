#
# Uli Meis <a.sporto+bee@gmail.com>
#
# Handy macro for fetching current tag or commit of a git repo.
#
MACRO(FIND_GIT_TAGORCOMMIT GITDIR CMAKEVAR)
  EXECUTE_PROCESS(COMMAND bash -c 
    "GITCOMMIT=`git-log | head -n1 | cut -d' ' -f2`;\\
     if [ -z \"$GITCOMMIT\" ]; then exit 1;fi; \\
     GITTAG=`cd .git/refs/tags && grep $GITCOMMIT * | cut -d: -f1` ;\\
     if [ -n \"$GITTAG\" ]; then \\
       echo -n $GITTAG | tr -d v; else \\
       echo -n git-$GITCOMMIT;fi"
    WORKING_DIRECTORY ${GITDIR} 
    OUTPUT_VARIABLE GIT_TAGORCOMMIT
    RESULT_VARIABLE GIT_TAGORCOMMITRET)
  IF(GIT_TAGORCOMMITRET EQUAL 0)
    SET(${CMAKEVAR} ${GIT_TAGORCOMMIT})
  ENDIF(GIT_TAGORCOMMITRET EQUAL 0)
ENDMACRO(FIND_GIT_TAGORCOMMIT)
