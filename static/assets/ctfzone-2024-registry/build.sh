#!/bin/bash
# This software is designed to flatten and minimize docker images. 
# It changes the base of the docker image and compresses 
# all the layers above it into a single layer.
set -uo pipefail

REPO=$1
IMAGE_DIR=$2
MAX_LAYERS_COUNT=5
SERVICE_PASSWORD=$(cat /configs/.service_password | tr -d '\n')

echo "Downloading $REPO to $IMAGE_DIR"
mkdir $IMAGE_DIR
skopeo login --tls-verify=false -u $SERVICE_USER -p $SERVICE_PASSWORD $REGISTRY_HOST:$REGISTRY_PORT
skopeo copy --tls-verify=false docker://$REGISTRY_HOST:$REGISTRY_PORT/$REPO:latest docker-archive://$IMAGE_DIR.tar

tar -C $IMAGE_DIR -xf $IMAGE_DIR.tar
rm -f $IMAGE_DIR.tar

CONFIGNAME=$(jq -r '.[0].Config' $IMAGE_DIR/manifest.json)

LAYERS_COUNT=$(jq -r '.rootfs.diff_ids | length' $IMAGE_DIR/$CONFIGNAME)
if [ $LAYERS_COUNT -gt $MAX_LAYERS_COUNT ]; then
  echo "Too many layers";
  exit 1
fi
LAYERS=$(jq -r ".rootfs.diff_ids[1:$MAX_LAYERS_COUNT][]" $IMAGE_DIR/$CONFIGNAME)
BASE_LAYER=$(jq -r ".rootfs.diff_ids[0]" $IMAGE_DIR/$CONFIGNAME | sed "s/sha256://g")

# unpack layers
cd $IMAGE_DIR
mkdir .overlay
i=1
for l in $LAYERS; do
  LAYER=$(printf "$l"| sed "s/sha256://g").tar
  echo $LAYER
  tar -C .overlay -xf $LAYER --overwrite
  i=$((i+1))
  rm -f $IMAGE_DIR/$LAYER
done

echo "creating tar from overlay"
tar -cf flattened.tar -C .overlay/ .
rm -rf .overlay/
FLATTENED=$(sha256sum flattened.tar | awk '{ printf $1 }')
mv flattened.tar $FLATTENED.tar

echo "replacing first layer with appropriate base"
NEW_BASE=$(sha256sum /app/base.tar | awk '{ printf $1 }')
rm -f "$IMAGE_DIR/$BASE_LAYER.tar"
cp /app/base.tar $IMAGE_DIR/$NEW_BASE.tar

echo "fixing configs"
jq -rM ".history |= [] | .rootfs.diff_ids |= [\"sha256:$NEW_BASE\",\"sha256:$FLATTENED\"]" $CONFIGNAME > $CONFIGNAME.new
rm -f $CONFIGNAME

# rename Config
CONFIGHASH=$(sha256sum $CONFIGNAME.new | awk '{ printf $1 }')
mv $CONFIGNAME.new $CONFIGHASH.json

# fix Config in manifest.json
sed -i "s/$CONFIGNAME/$CONFIGHASH.json/g" $IMAGE_DIR/manifest.json

# fix layers in manifest.json
jq -rM ".[0].Layers |= [\"$NEW_BASE.tar\",\"$FLATTENED.tar\"]" $IMAGE_DIR/manifest.json > $IMAGE_DIR/manifest.json.new
rm -f manifest.json
mv -f manifest.json.new manifest.json

find . -type d -exec rm -rf {} ';' 2>/dev/null

tar -cf $IMAGE_DIR.tar -C $IMAGE_DIR .
rm -rf $IMAGE_DIR
echo "image builed: $IMAGE_DIR.tar, pushing to $REGISTRY_HOST:$REGISTRY_PORT/$REPO:latest"
skopeo copy --tls-verify=false docker-archive://$IMAGE_DIR.tar docker://$REGISTRY_HOST:$REGISTRY_PORT/$REPO:latest
