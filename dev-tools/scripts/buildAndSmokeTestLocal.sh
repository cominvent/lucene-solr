#!/usr/bin/env bash
# Simple script to first build releases and then smoke test locally, all in one go
usage() {
  echo "Usage: ./buildAndSmokeTestLocal.sh <version> [<revision>]"
  exit 1
}
DIR=/tmp/lucene-dist/
VER=$1
REV=$2
if [[ ! $VER ]] ; then
  usage 
fi
if [[ ! $REV ]] ; then
  echo "Using current HEAD revision"
  REV=$(git rev-parse HEAD) 
fi
echo -n $REV >/tmp/lucene-revision
echo "==== Will build not-signed release artifacts for version $VER and revision $REV into $DIR and then smoke test locally ===="

rm -rf $DIR >/dev/null
mkdir -p $DIR
cd lucene
echo
echo "==== Building Lucene ===="
ANT_OPTS="-Xmx256m -XX:+CMSClassUnloadingEnabled -XX:MaxPermSize=128M" ant -Dversion=$VER prepare-release-no-sign
mv dist $DIR/lucene
cd ../solr 
echo
echo "==== Building Solr ===="
ANT_OPTS="-Xmx256m -XX:+CMSClassUnloadingEnabled -XX:MaxPermSize=128M" ant -Dversion=$VER prepare-release-no-sign
mv package $DIR/solr
cd ..
echo
echo "==== Smoke testing ===="
python3 -u dev-tools/scripts/smokeTestRelease.py --revision $REV --version $VER --not-signed file://$DIR
