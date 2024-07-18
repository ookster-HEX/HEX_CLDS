# Chicken Olivewanders

Andrew's and Thomas's website for buying wands

docker run -v /home/pi/web/chicken-olivewanders:/home/web/app -p 3000:5000 -e WEB_APP_DIR=app -restart=always -d --name web --network webnet genericweb:latest

docker run -p 80:80 --restart=always -d -name nginx --network webnet nginx:latest

flask db migrate -m "users table"
flask db upgrade