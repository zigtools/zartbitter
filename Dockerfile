FROM mcr.microsoft.com/dotnet/sdk:7.0

COPY ./zartbitter /src

RUN cd /src && dotnet build -c Release

RUN cp -Tr /src/bin/Release/net7.0 /app

CMD [ "/data/zartbitter.cfg" ]
ENTRYPOINT [ "/app/zartbitter" ]
