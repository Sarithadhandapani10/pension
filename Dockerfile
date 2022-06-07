FROM openjdk:8
EXPOSE 8104
ADD target/Authorization-Microservice-0.0.1-SNAPSHOT.jar Authorization-Microservice-0.0.1-SNAPSHOT.jar 
ENTRYPOINT ["java","-jar","/Authorization-Microservice-0.0.1-SNAPSHOT.jar"]