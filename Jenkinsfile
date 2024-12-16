#!groovy

pipeline {
    agent none
    environment {
        PROJECT_NAME = 'kaos'
        TILLER_NAMESPACE = 'tiller'
        ADMIN_GROUP = 'TFS_NETWORKTEAM_CONTRIB'
    }

    stages {
        stage('Begin Build') {
            agent { label 'linux-container' }
            steps {
                script {
                    beginBuild()
                    env.GIT_COMMIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    if (!env.ADMIN_GROUP?.trim()) {
                        raiseBuildError message: "Please fill out ADMIN_GROUP variable in Jenkinsfile"
                    }
                }
            }
        }
        stage('Build') {
            agent { label 'linux-container' }
            environment {
                IMAGE_REGISTRY = "artifactory.genmills.com/docker-snapshot-local"
            }
            steps {
                sh 'docker build . -t $IMAGE_REGISTRY/$PROJECT_NAME:$BUILD_NUMBER-$GIT_COMMIT_SHORT'
                pushToArtifactoryContainerImage image: "$PROJECT_NAME", tag: "$BUILD_NUMBER-$GIT_COMMIT_SHORT"
            }
        }
        stage('Development') {
            agent { label 'linux-container' }
            environment {
                GMI_ENVIRONMENT = "Development"
                IMAGE_REGISTRY = "docker.generalmills.com"
            }
            steps {
                withKubeConfig(credentialsId: 'openshift', serverUrl: 'https://openshift-dev.genmills.com:8443') {
                    sh 'oc project $PROJECT_NAME || \
                        (oc new-project $PROJECT_NAME \
                            && oc policy add-role-to-user edit "system:serviceaccount:$TILLER_NAMESPACE:tiller" \
                            && oc adm policy add-role-to-group admin $ADMIN_GROUP -n $PROJECT_NAME)'

                    sh 'oc adm policy add-scc-to-user nonroot -z default' // Making the container not run as root

                    dir("release/$PROJECT_NAME") {
                        sh 'helm delete --purge $PROJECT_NAME || true'
                        sh 'helm dependency update'
                        sh 'helm init'
                        sh 'helm upgrade -i $PROJECT_NAME . \
                                            --namespace $PROJECT_NAME \
                                            --values values.yaml \
                                            --set image.tag=$PROJECT_NAME:$BUILD_NUMBER-$GIT_COMMIT_SHORT \
                                            --set image.repository=$IMAGE_REGISTRY \
                                            --set gmiEnvironment=$GMI_ENVIRONMENT \
                                            --set repository=$IMAGE_REGISTRY \
                                            --set ingress.hosts[0].host=$PROJECT_NAME.openshift-dev.genmills.com'
                    }
                }
            }
        }
        stage('Production') {
            agent { label 'linux-container' }
            environment {
                GMI_ENVIRONMENT = "Production"
                IMAGE_REGISTRY = "docker.generalmills.com"
            }
            when {
                branch 'master'
                beforeInput true
            }
            options { timeout(time: 1, unit: 'DAYS') }
            input {
                message 'Deploy to Production?'
                //submitter 'GBS-IT ALL APPLICATION DEVELOPERS' // submitter limits who can "approve", use AD groups or email seperated by commas
            }
            steps {
                promoteContainerImage image: "$PROJECT_NAME", tag: "$BUILD_NUMBER-$GIT_COMMIT_SHORT"

                withKubeConfig(credentialsId: 'openshift', serverUrl: 'https://openshift.genmills.com:8443') {
                    sh 'oc project $PROJECT_NAME || \
                        (oc new-project $PROJECT_NAME \
                            && oc policy add-role-to-user edit "system:serviceaccount:$TILLER_NAMESPACE:tiller" \
                            && oc adm policy add-role-to-group admin $ADMIN_GROUP -n $PROJECT_NAME)'

                    sh 'oc adm policy add-scc-to-user nonroot -z default' // Making the container not run as root

                    dir('release') {
                        sh 'helm upgrade -i $PROJECT_NAME $PROJECT_NAME \
                                            --namespace $PROJECT_NAME \
                                            --values $PROJECT_NAME/values.yaml \
                                            --set image.tag=$BUILD_NUMBER-$GIT_COMMIT_SHORT \
                                            --set image.repository=$IMAGE_REGISTRY \
                                            --set gmiEnvironment=$GMI_ENVIRONMENT \
                                            --set repository=$IMAGE_REGISTRY \
                                            --set ingress.hosts[0].host=$PROJECT_NAME.openshift.genmills.com'
                    }
                }
            }
        }
    }
}

