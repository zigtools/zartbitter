FROM mcr.microsoft.com/dotnet/sdk:7.0

COPY ./zartbitter /src

RUN cd /src && dotnet build -c Release

RUN cp -Tr /src/bin/Release/net7.0 /app

RUN apt-get update -y && apt-get install -y sqlite3

RUN apt-get clean autoclean \
  && apt-get autoremove --yes \
  && rm -rf /var/lib/{apt,dpkg,cache,log}/

CMD [ "/data/zartbitter.cfg" ]
ENTRYPOINT [ "/app/zartbitter" ]
