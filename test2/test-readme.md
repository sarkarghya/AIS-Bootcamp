## layers

Let's build a simple docker version. Look at test2.py. This file just downloads a few layers from a public repo and unzips them.

this by itself isn't very useful. We want to run these, and to do this, we need to be able to chroot. You can't chroot on macos for 
sad reasons, so the workaround is to use docker with --privileged

## chroot

Build the docker image `docker build . -t mydocker`

Then, run it `docker run --privileged -it mydocker /bin/bash`

if you are not on macos, you can try skipping the docker part. for compatibility, we will use docker for everything.

### test2.py
Run `python test2.py` to download the layers. You now have python3.12 in extracted_python

### running the extracted image
simply `chroot extracted_python/` to get into a terminal inside the image you just downloaded.

You can see that this is actually different by running `python --version` and seeing that it is 3.12, not the version of python in the docker container that is running this chroot.

## cgroups

run with 
```shell
docker compose up --build
```

Then, run
```shell
mkdir -p /sys/fs/cgroup/demo
cd /sys/fs/cgroup
echo "+cpu +memory +pids" > cgroup.subtree_control
cd demo
echo "1000000" > memory.max
cd /w2d2
```

Then, run inside the chroot `sh -c 'echo $$ > /sys/fs/cgroup/demo/cgroup.procs && chroot extracted_python/'`
```shell
# Inside chroot
python3 -c "
data = []
for i in range(100):
    data.append('x' * 10 * 1024 * 1024)  # 10MB chunks
    print(f'Allocated {(i+1)*10}MB', flush=True)
"
```

I think there is some weird optimization happening here because it should be crashing much sooner. Test this with data.append(random) to see if it crashes sooner. you can also `echo "100M" > memory.max`