const gulp = require("gulp");
const gts = require("gulp-typescript");
const gsm = require("gulp-sourcemaps");
const ws = require("webpack-stream");
const clean = require("gulp-clean");

// Top level tasks:
gulp.task("default", ["build"]);
gulp.task("build", ["build-src", "build-test"]);
gulp.task("dist", ["build-src", "dist-files"]);
gulp.task("clean", task_clean);

// Supportive tasks:
gulp.task("build-src", task_build_src);
gulp.task("build-test", task_build_test);
gulp.task("dist-files", ["build-src"], task_dist_files);

function task_build_src() {
	const wscfg = require("./src/webpack.config.js");
	delete wscfg.entry;
	delete wscfg.output.path;
	return gulp.src("./src/entry.ts")
		.pipe(ws(wscfg))
		.pipe(gulp.dest("./out/webpack"));
}

function task_build_test() {
	tsp = gts.createProject("./test/tsconfig.json");
	tsr = tsp.src()
		.pipe(gsm.init())
		.pipe(tsp());
	return tsr.js
		.pipe(gsm.write())
		.pipe(gulp.dest(tsp.options.outDir));
}

function task_compress() {
	return gulp.src("./out/webpack/pe-struct.js")
		.pipe(uglify()).on("error", (e) => { console.log(e) })
		.pipe(gulp.dest("./dist"))
		.pipe(ren("pe-struct.min.js"))
		;
}

function task_dist_files() {
	return gulp.src([
		"./out/webpack/pe-struct.js",
		"./def/pe-struct.d.ts"
	])
		.pipe(gulp.dest("./dist"));
}

function task_clean() {
	return gulp.src(["./out", "./dist"])
		.pipe(clean());
}
