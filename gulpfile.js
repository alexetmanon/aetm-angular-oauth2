var gulp = require('gulp'),
    uglify = require('gulp-uglify'),
    rename = require('gulp-rename');

var sources = [
    "dist/aetm-angular-oauth2.js"
];

gulp.task('uglify', function() {
    return gulp
        .src(sources)
        .pipe(uglify())
        .pipe(rename({
            suffix: '.min'
        }))
        .pipe(gulp.dest('dist'));
});

gulp.task('build', ['uglify']);

gulp.task('default', ['build']);