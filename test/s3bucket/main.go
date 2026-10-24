// Command s3bucket creates a bucket with versioning and object lock on an S3-compatible endpoint (backup drill).
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func main() {
	endpoint := flag.String("endpoint", "127.0.0.1:9000", "host:port")
	bucket := flag.String("bucket", "porch-backups", "bucket name")
	flag.Parse()
	c, err := minio.New(*endpoint, &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("S3_ACCESS_KEY"), os.Getenv("S3_SECRET_KEY"), ""), Secure: false})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Object lock implies versioning.
	if err := c.MakeBucket(ctx, *bucket, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
		log.Fatal(err)
	}
	log.Printf("bucket %s created with versioning and object lock", *bucket)
}
