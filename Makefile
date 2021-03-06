# Copyright 2019 Decipher Technology Studios
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: build
build:
	@echo "---> Generating assets."
	@go generate
	@echo "---> Building binaries."
	@go build -o ldapt -ldflags "-X main.commit=$(git rev-parse --verify --short HEAD) -X main.version=$(cat VERSION)" 


.PHONY: docker
docker:
	@echo "---> Building docker image."
	@docker build -t "deciphernow/ldapt:$(shell cat VERSION)" -f ./docker/Dockerfile .
