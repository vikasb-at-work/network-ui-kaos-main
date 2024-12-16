server = 'vl-kaosdev01';
port = 8080;
version = 0.1;
protocol = 'http';

uri = protocol+'://'+server+':'+port.toString()+'/api/'+version.toString()+'/';

const rest = async (request) => {
        const response = await fetch(request);
		const myJson = await response.json();
		return (myJson);
}

function samurai_get_years() {
		const request = uri+'samurai/get_years';
		result = rest(request);
		return result;
}

function samurai_year(item="MGOR1", year="Year 0") {
		const request = uri+'samurai/year/'+item+'/'+year;
		result = rest(request);
		return result;
}
