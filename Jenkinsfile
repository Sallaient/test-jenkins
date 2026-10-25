// Job 1: "kri-pull" -- updates a local clone of the repo on the node, runs the tests,
// and triggers the compute job only if they pass.
// Job 2 ("kri-compute", freestyle) reads from that clone.
pipeline {
    agent any

    options {
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'REPO_URL', defaultValue: 'https://github.com/Sallaient/test-jenkins', description: 'Git repository URL')
        string(name: 'BRANCH', defaultValue: 'main', description: 'Branch to pull')
        string(name: 'CREDENTIALS_ID', defaultValue: '', description: 'Jenkins credentials ID (empty for public repos)')
    }

    environment {
        // Fixed location on the Jenkins node, shared with the compute job.
        // The jenkins user must be able to write here.
        TARGET_DIR = '/var/lib/jenkins/kri-repo'
        PYTHONDONTWRITEBYTECODE = '1'   // keep the shared clone free of __pycache__
    }

    stages {
        stage('Pull') {
            steps {
                // dir() creates the folder if needed; the git step clones the
                // first time and fetches/updates on later runs.
                dir(env.TARGET_DIR) {
                    script {
                        def opts = [url: params.REPO_URL, branch: params.BRANCH]
                        if (params.CREDENTIALS_ID?.trim()) {
                            opts.credentialsId = params.CREDENTIALS_ID
                        }
                        git(opts)
                    }
                    sh 'git log -1 --oneline'
                }
            }
        }

        stage('Test') {
            steps {
                sh '''
                    # venv lives in this job's workspace and is reused between builds
                    [ -d .venv ] || python3 -m venv .venv
                    . .venv/bin/activate
                    pip install -q -r "$TARGET_DIR/requirements.txt"
                    cd "$TARGET_DIR"
                    pytest -q -p no:cacheprovider --junitxml="$WORKSPACE/test-results.xml"
                '''
            }
            post {
                always { junit 'test-results.xml' }
            }
        }
    }
}