FROM ubuntu:18.04 as sgxbase
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN apt-get update && apt-get install -y \
    gnupg \
    wget

RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' > /etc/apt/sources.list.d/intel-sgx.list
RUN wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN apt-get update 

FROM sgxbase as sgx_sample_builder
# App build time dependencies
RUN apt-get install -y build-essential

WORKDIR /opt/intel
COPY ./sgx_linux_x64_sdk_2.17.101.1.bin /opt/intel
RUN chmod +x sgx_linux_x64_sdk_2.17.101.1.bin
RUN echo 'yes' | ./sgx_linux_x64_sdk_2.17.101.1.bin

FROM sgxbase as aesm 
RUN apt-get install -y \
    libcurl4 \
    libprotobuf10 \
    libssl1.1 \
    make \
    module-init-tools
RUN apt-get install -y libsgx-aesm-launch-plugin

WORKDIR /opt/intel/sgx-aesm-service/aesm
ENV LD_LIBRARY_PATH=.
CMD ./aesm_service --no-daemon

FROM sgxbase as chall
RUN apt-get install -y \
    libcurl4 \
    libprotobuf10 \
    libssl1.1
RUN apt-get install -y --no-install-recommends libsgx-launch libsgx-urts

# Chall config
WORKDIR /
RUN apt-get install -y lib32z1 xinetd

COPY ./chall.xinetd /etc/xinetd.d/chall
COPY ./start.sh /start.sh
RUN echo "Connection Blocked" > /etc/banner_fail

RUN chmod +x /start.sh

COPY ./bin/ /
RUN chown root:root /basic_guide /cases.signed.so && \
    chmod 750 /basic_guide && \
    chmod 640 /cases.signed.so

CMD ["/start.sh"]

EXPOSE 9999